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
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>

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
		// After a timeout on a buffer, do not wait for it again for this long: a quiet worker that
		// sleeps in the engine does not publish anything, and every clone/evaluation that depends
		// on it would stall for the whole timeout.
		uint64_t backoff_ns = 50'000'000;
		bool enabled = true;
		// Fork snapshot handoff (see below).
		bool handoff_enabled = true;
		// Maximum number of pending handoff entries (snapshots and claims), over all shards.
		size_t handoff_max_entries = 1024;
		// An entry older than this (in event time, relative to the newest entry of its shard) is
		// dropped: it bounds the memory held by snapshots nobody consumed.
		uint64_t handoff_ttl_ns = 10'000'000'000;
		// The largest distance between the clone exit of the parent and the one of the child for
		// an entry to be matched (protects against the reuse of a tid).
		uint64_t handoff_match_ns = 2'000'000'000;
	};

	// The state a child inherits, captured by the parent's worker. Opaque for this class.
	using payload_t = std::unique_ptr<void, void (*)(void*)>;
	static payload_t no_payload() { return payload_t(nullptr, [](void*) {}); }

	struct stats {
		uint64_t waits;     // waits that were not satisfied by the first check
		uint64_t timeouts;  // waits that gave up
		uint64_t wait_ns;   // total time spent in the waits that were not immediate
		uint64_t skipped;   // waits not even started because of the backoff after a timeout
	};

	struct handoff_stats {
		uint64_t put;           // snapshots taken by a parent
		uint64_t consumed;      // snapshots used by a child
		uint64_t live_copies;   // children that had no snapshot and copied the live parent
		uint64_t skipped_puts;  // parents that found the child already created and did not copy
		uint64_t dropped;       // entries dropped because of the size limit or the age
		uint64_t pending;       // entries currently held
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

	// --- fork snapshot handoff ---
	// The watermark wait cannot fix this: the parent opens an fd AFTER the clone, but its worker
	// is AHEAD of the one of the child, so the clone exit of the child (which copies the live state
	// of the parent) sees the fd. The fix: the worker of the parent captures the state the child
	// inherits while it processes its own clone exit, in order with the parent's later events, and
	// hands it over keyed by the child tid. The child uses the snapshot instead of the live parent.
	//
	// If the child gets there first it copies the live parent (after the watermark wait) and
	// leaves a claim: the parent then neither copies nor publishes anything. The claim section
	// and the publication of the snapshot are serialized by a shard lock, so the parent cannot
	// proceed to its next event while the child is reading the live parent.
	// Every entry carries the event time of its creation; the entries older than the ttl are
	// dropped, and so are the oldest ones when the maximum size is exceeded (a snapshot that is
	// never consumed, e.g. because the child event was lost, never accumulates).
	bool handoff_enabled() const { return enabled() && m_cfg.handoff_enabled; }

	// Parent side, before copying: true if the child was created already (it left a claim).
	bool handoff_child_done(int64_t child_tid, int64_t parent_tid, uint64_t ts);
	// Parent side: publishes the snapshot. Returns false (and drops it) if the child claimed
	// the slot in the meantime.
	bool handoff_put(int64_t child_tid, int64_t parent_tid, uint64_t ts, payload_t payload);
	// Child side: the snapshot of the parent, or an empty payload.
	payload_t handoff_take(int64_t child_tid, int64_t parent_tid, uint64_t ts);
	// Child side, no snapshot: runs `copy_live` (which copies the live parent) under the shard
	// lock and leaves a claim, unless `copy_live` returns an empty payload.
	payload_t handoff_claim_live(int64_t child_tid,
	                             int64_t parent_tid,
	                             uint64_t ts,
	                             const std::function<payload_t()>& copy_live);

	handoff_stats get_handoff_stats() const;
	size_t handoff_pending() const;

private:
	bool wait_slow(uint16_t target, uint64_t ts);

	static constexpr size_t HANDOFF_SHARDS = 16;
	struct handoff_entry {
		int64_t parent_tid;
		uint64_t ts;
		uint64_t seq;
		payload_t payload;  // empty: the child claimed the slot
	};
	struct alignas(64) handoff_shard {
		mutable std::mutex mtx;
		std::unordered_map<int64_t, handoff_entry> map;
		std::deque<std::pair<int64_t, uint64_t>> order;  // (child tid, seq), oldest first
		uint64_t next_seq = 0;
	};
	handoff_shard& shard_of(int64_t child_tid) {
		return m_handoff[static_cast<uint64_t>(child_tid) % HANDOFF_SHARDS];
	}
	// Returns the live entry for the child, erasing it if stale (too old or another parent).
	handoff_entry* find_fresh(handoff_shard& sh,
	                          int64_t child_tid,
	                          int64_t parent_tid,
	                          uint64_t ts);
	void insert_locked(handoff_shard& sh,
	                   int64_t child_tid,
	                   int64_t parent_tid,
	                   uint64_t ts,
	                   payload_t payload);

	struct alignas(64) slot {
		std::atomic<uint64_t> wm{0};
		// steady-clock time (ns) before which waits on this buffer are skipped
		std::atomic<uint64_t> skip_until{0};
	};

	config m_cfg;
	clock_fn m_clock;
	uint16_t m_n_buffers = 0;
	std::unique_ptr<slot[]> m_slots;
	std::atomic<uint64_t> m_waits{0};
	std::atomic<uint64_t> m_timeouts{0};
	std::atomic<uint64_t> m_skipped{0};
	std::atomic<uint64_t> m_wait_ns{0};

	handoff_shard m_handoff[HANDOFF_SHARDS];
	std::atomic<uint64_t> m_h_put{0};
	std::atomic<uint64_t> m_h_consumed{0};
	std::atomic<uint64_t> m_h_live{0};
	std::atomic<uint64_t> m_h_skipped{0};
	std::atomic<uint64_t> m_h_dropped{0};
};
