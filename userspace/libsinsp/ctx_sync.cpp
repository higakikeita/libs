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

#include <libsinsp/ctx_sync.h>
#include <libsinsp/utils.h>

#include <algorithm>
#include <chrono>
#include <thread>

sinsp_ctx_sync::sinsp_ctx_sync(): m_clock(&sinsp_utils::get_current_time_ns) {}

void sinsp_ctx_sync::init(uint16_t n_buffers) {
	m_n_buffers = n_buffers;
	m_slots = n_buffers > 0 ? std::make_unique<slot[]>(n_buffers) : nullptr;
	for(auto& sh : m_handoff) {
		std::lock_guard<std::mutex> lock(sh.mtx);
		sh.map.clear();
		sh.order.clear();
	}
	reset_stats();
}

bool sinsp_ctx_sync::wait_slow(uint16_t target, uint64_t ts) {
	using clk = std::chrono::steady_clock;
	const auto start = clk::now();
	const uint64_t start_ns =
	        std::chrono::duration_cast<std::chrono::nanoseconds>(start.time_since_epoch()).count();
	if(start_ns < m_slots[target].skip_until.load(std::memory_order_relaxed)) {
		m_skipped.fetch_add(1, std::memory_order_relaxed);
		return false;
	}
	const auto deadline = start + std::chrono::nanoseconds(m_cfg.timeout_ns);
	const auto& wm = m_slots[target].wm;
	bool ok = false;
	// Spin for a few microseconds, then yield the CPU for up to 2 ms (a plain sleep wakes up about
	// a millisecond late on a typical kernel, which would dominate the wait), then sleep.
	constexpr auto spin_phase = std::chrono::microseconds(20);
	constexpr auto yield_phase = std::chrono::milliseconds(2);
	for(;;) {
		if(wm.load(std::memory_order_acquire) >= ts) {
			ok = true;
			break;
		}
		const auto now = clk::now();
		if(now >= deadline) {
			break;
		}
		const auto elapsed = now - start;
		if(elapsed < spin_phase) {
#if defined(__x86_64__) || defined(__i386__)
			__builtin_ia32_pause();
#elif defined(__aarch64__)
			__asm__ __volatile__("yield");
#endif
		} else if(elapsed < yield_phase) {
			std::this_thread::yield();
		} else {
			std::this_thread::sleep_for(std::chrono::microseconds(100));
		}
	}
	m_waits.fetch_add(1, std::memory_order_relaxed);
	m_wait_ns.fetch_add(
	        std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now() - start).count(),
	        std::memory_order_relaxed);
	if(!ok) {
		m_timeouts.fetch_add(1, std::memory_order_relaxed);
		m_slots[target].skip_until.store(start_ns + m_cfg.timeout_ns + m_cfg.backoff_ns,
		                                 std::memory_order_relaxed);
	}
	return ok;
}

sinsp_ctx_sync::stats sinsp_ctx_sync::get_stats() const {
	return {m_waits.load(std::memory_order_relaxed),
	        m_timeouts.load(std::memory_order_relaxed),
	        m_wait_ns.load(std::memory_order_relaxed),
	        m_skipped.load(std::memory_order_relaxed)};
}

void sinsp_ctx_sync::reset_stats() {
	m_waits = 0;
	m_timeouts = 0;
	m_wait_ns = 0;
	m_skipped = 0;
	m_h_put = 0;
	m_h_consumed = 0;
	m_h_live = 0;
	m_h_skipped = 0;
	m_h_dropped = 0;
}

sinsp_ctx_sync::handoff_entry* sinsp_ctx_sync::find_fresh(handoff_shard& sh,
                                                          int64_t child_tid,
                                                          int64_t parent_tid,
                                                          uint64_t ts) {
	const auto it = sh.map.find(child_tid);
	if(it == sh.map.end()) {
		return nullptr;
	}
	const uint64_t dist = ts > it->second.ts ? ts - it->second.ts : it->second.ts - ts;
	if(it->second.parent_tid != parent_tid || dist > m_cfg.handoff_match_ns) {
		// A previous use of the same tid, or an entry nobody consumed.
		sh.map.erase(it);
		m_h_dropped.fetch_add(1, std::memory_order_relaxed);
		return nullptr;
	}
	return &it->second;
}

void sinsp_ctx_sync::insert_locked(handoff_shard& sh,
                                   int64_t child_tid,
                                   int64_t parent_tid,
                                   uint64_t ts,
                                   payload_t payload) {
	const size_t max_per_shard = std::max<size_t>(1, m_cfg.handoff_max_entries / HANDOFF_SHARDS);
	// Oldest first: drop what is expired or beyond the size limit. Stale `order` records (the
	// entry was consumed or replaced) are just skipped.
	while(!sh.order.empty()) {
		const auto [tid, seq] = sh.order.front();
		const auto it = sh.map.find(tid);
		const bool live = it != sh.map.end() && it->second.seq == seq;
		if(live && sh.map.size() < max_per_shard && it->second.ts + m_cfg.handoff_ttl_ns >= ts) {
			break;
		}
		if(live) {
			sh.map.erase(it);
			m_h_dropped.fetch_add(1, std::memory_order_relaxed);
		}
		sh.order.pop_front();
	}
	const uint64_t seq = sh.next_seq++;
	sh.map.insert_or_assign(child_tid, handoff_entry{parent_tid, ts, seq, std::move(payload)});
	sh.order.emplace_back(child_tid, seq);
}

bool sinsp_ctx_sync::handoff_child_done(int64_t child_tid, int64_t parent_tid, uint64_t ts) {
	auto& sh = shard_of(child_tid);
	std::lock_guard<std::mutex> lock(sh.mtx);
	auto* e = find_fresh(sh, child_tid, parent_tid, ts);
	if(e == nullptr || e->payload) {
		return false;
	}
	sh.map.erase(child_tid);
	m_h_skipped.fetch_add(1, std::memory_order_relaxed);
	return true;
}

bool sinsp_ctx_sync::handoff_put(int64_t child_tid,
                                 int64_t parent_tid,
                                 uint64_t ts,
                                 payload_t payload) {
	auto& sh = shard_of(child_tid);
	std::lock_guard<std::mutex> lock(sh.mtx);
	if(auto* e = find_fresh(sh, child_tid, parent_tid, ts); e != nullptr && !e->payload) {
		sh.map.erase(child_tid);  // the child claimed the slot while we were copying
		m_h_skipped.fetch_add(1, std::memory_order_relaxed);
		return false;
	}
	insert_locked(sh, child_tid, parent_tid, ts, std::move(payload));
	m_h_put.fetch_add(1, std::memory_order_relaxed);
	return true;
}

sinsp_ctx_sync::payload_t sinsp_ctx_sync::handoff_take(int64_t child_tid,
                                                       int64_t parent_tid,
                                                       uint64_t ts) {
	auto& sh = shard_of(child_tid);
	std::lock_guard<std::mutex> lock(sh.mtx);
	auto* e = find_fresh(sh, child_tid, parent_tid, ts);
	if(e == nullptr || !e->payload) {
		return no_payload();
	}
	auto payload = std::move(e->payload);
	sh.map.erase(child_tid);
	m_h_consumed.fetch_add(1, std::memory_order_relaxed);
	return payload;
}

sinsp_ctx_sync::payload_t sinsp_ctx_sync::handoff_claim_live(
        int64_t child_tid,
        int64_t parent_tid,
        uint64_t ts,
        const std::function<payload_t()>& copy_live) {
	auto& sh = shard_of(child_tid);
	std::lock_guard<std::mutex> lock(sh.mtx);
	if(auto* e = find_fresh(sh, child_tid, parent_tid, ts); e != nullptr && e->payload) {
		auto payload = std::move(e->payload);  // published while we were waiting
		sh.map.erase(child_tid);
		m_h_consumed.fetch_add(1, std::memory_order_relaxed);
		return payload;
	}
	auto payload = copy_live();
	if(payload) {
		insert_locked(sh, child_tid, parent_tid, ts, no_payload());
		m_h_live.fetch_add(1, std::memory_order_relaxed);
	}
	return payload;
}

sinsp_ctx_sync::handoff_stats sinsp_ctx_sync::get_handoff_stats() const {
	return {m_h_put.load(std::memory_order_relaxed),
	        m_h_consumed.load(std::memory_order_relaxed),
	        m_h_live.load(std::memory_order_relaxed),
	        m_h_skipped.load(std::memory_order_relaxed),
	        m_h_dropped.load(std::memory_order_relaxed),
	        handoff_pending()};
}

size_t sinsp_ctx_sync::handoff_pending() const {
	size_t n = 0;
	for(const auto& sh : m_handoff) {
		std::lock_guard<std::mutex> lock(sh.mtx);
		n += sh.map.size();
	}
	return n;
}
