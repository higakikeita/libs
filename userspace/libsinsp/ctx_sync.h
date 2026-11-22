// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

/**
 * @brief Cross-partition "context synchronization" of the multi-worker mode (prototype).
 *
 * In multi-worker mode the kernel routes the events to the buffers by TGID, and every buffer is
 * consumed by its own worker. Nothing orders the events of different buffers, but a worker
 * sometimes needs the state of a thread that belongs to another buffer (the clone exit of a child
 * copies the state of its parent). This class lets a worker wait until another buffer has
 * processed everything that happened up to a given timestamp.
 *
 * Every buffer publishes a watermark W: "this buffer has completely processed all its events with
 * a timestamp lower than W". The watermark is:
 *  - the timestamp of the event the worker is processing, published (release) right after the event
 *    is fetched and before it is parsed (the events before it are therefore fully processed);
 *  - when the worker finds the buffer empty, `t0 - margin`, where t0 was sampled BEFORE the buffer
 *    was inspected (an empty buffer does not later receive an event older than `margin`);
 *  - UINT64_MAX once the buffer reached the end of the capture.
 *
 * Deadlock freedom: a worker W1 processing an event with timestamp T1 publishes T1 before it can
 * wait, and it only waits for a watermark >= T1 (the timestamp of the event it is processing).
 * A wait on a buffer that is itself blocked on an event with timestamp T2 is satisfied when
 * T2 >= T1. A cycle of waits would need T1 > T2 > ... > T1, which is impossible (equal timestamps
 * satisfy the wait). Workers that do not advance (not started, stuck in a long callback) cannot
 * block anybody forever either: the wait is bounded by a timeout, after which the caller falls
 * back to the single-partition behavior and a counter is incremented.
 */
class sinsp_ctx_sync {
public:
	static constexpr uint16_t INVALID_BUFFER = UINT16_MAX;

	struct config {
		// Maximum time a worker waits for another buffer.
		uint64_t timeout_ns = 3'000'000;
		// Safety margin subtracted from the clock when a buffer is idle.
		uint64_t margin_ns = 1'000'000;
		bool enabled = true;
	};

	struct stats {
		uint64_t waits;     // waits that were not satisfied by the first check
		uint64_t timeouts;  // waits that gave up
		uint64_t wait_ns;   // total time spent in the waits that were not immediate
	};

	using clock_fn = std::function<uint64_t()>;

	sinsp_ctx_sync();

	// The buffer (0-based, among the non-default buffers) that receives the events of a thread
	// group. This is THE place that knows the routing done by the modern BPF probe
	// (`ringbuf_id = tgid % ringbufs_num`); the test harness uses it too.
	static uint16_t buffer_index_for_tgid(int64_t tgid, uint16_t n_buffers) {
		return n_buffers == 0 ? INVALID_BUFFER
		                      : static_cast<uint16_t>(static_cast<uint64_t>(tgid) % n_buffers);
	}

	// Called once when the inspector opens, before any worker runs.
	void init(uint16_t n_buffers);
	uint16_t n_buffers() const { return m_n_buffers; }
	bool enabled() const { return m_cfg.enabled && m_n_buffers > 0; }

	void set_config(const config& cfg) { m_cfg = cfg; }
	const config& get_config() const { return m_cfg; }

	// Replace the clock used to publish the idle watermark (default: wall clock in ns, the domain
	// of the event timestamps of a live capture). Tests use a controlled clock.
	void set_clock(clock_fn fn) { m_clock = std::move(fn); }
	uint64_t now() const { return m_clock(); }

	// --- publisher side: only the worker of `idx` calls these ---
	// The worker is about to parse an event with timestamp `ts`.
	void publish_event(uint16_t idx, uint64_t ts) {
		auto& w = m_slots[idx].wm;
		if(ts > w.load(std::memory_order_relaxed)) {
			w.store(ts, std::memory_order_release);
		}
	}
	// The worker found its buffer empty; `t0` was sampled before looking at the buffer.
	void publish_idle(uint16_t idx, uint64_t t0) {
		if(t0 > m_cfg.margin_ns) {
			publish_event(idx, t0 - m_cfg.margin_ns);
		}
	}
	void publish_eof(uint16_t idx) { m_slots[idx].wm.store(UINT64_MAX, std::memory_order_release); }

	uint64_t watermark(uint16_t idx) const {
		return m_slots[idx].wm.load(std::memory_order_acquire);
	}

	// --- waiter side ---
	// Waits until the buffer `target` has a watermark >= `ts`. Never waits on `own` (the buffer of
	// the caller) or on an invalid buffer. Returns false only on timeout. The fast path is a single
	// acquire load.
	bool wait_for(uint16_t own, uint16_t target, uint64_t ts) {
		if(!enabled() || target == own || target >= m_n_buffers ||
		   m_slots[target].wm.load(std::memory_order_acquire) >= ts) {
			return true;
		}
		return wait_slow(target, ts);
	}

	stats get_stats() const;
	void reset_stats();

private:
	bool wait_slow(uint16_t target, uint64_t ts);

	struct alignas(64) slot {
		std::atomic<uint64_t> wm{0};
	};

	config m_cfg;
	clock_fn m_clock;
	uint16_t m_n_buffers = 0;
	std::unique_ptr<slot[]> m_slots;
	std::atomic<uint64_t> m_waits{0};
	std::atomic<uint64_t> m_timeouts{0};
	std::atomic<uint64_t> m_wait_ns{0};
};
