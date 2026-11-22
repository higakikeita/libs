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

#include <chrono>
#include <thread>

sinsp_ctx_sync::sinsp_ctx_sync(): m_clock(&sinsp_utils::get_current_time_ns) {}

void sinsp_ctx_sync::init(uint16_t n_buffers) {
	m_n_buffers = n_buffers;
	m_slots = n_buffers > 0 ? std::make_unique<slot[]>(n_buffers) : nullptr;
	reset_stats();
}

bool sinsp_ctx_sync::wait_slow(uint16_t target, uint64_t ts) {
	using clk = std::chrono::steady_clock;
	const auto start = clk::now();
	const auto deadline = start + std::chrono::nanoseconds(m_cfg.timeout_ns);
	const auto& wm = m_slots[target].wm;
	bool ok = false;
	// Spin, then yield, then sleep for short times: the common wait is a few microseconds.
	for(uint32_t i = 0;; i++) {
		if(wm.load(std::memory_order_acquire) >= ts) {
			ok = true;
			break;
		}
		if(i < 200) {
#if defined(__x86_64__) || defined(__i386__)
			__builtin_ia32_pause();
#elif defined(__aarch64__)
			__asm__ __volatile__("yield");
#endif
		} else if(i < 400) {
			std::this_thread::yield();
		} else {
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}
		if((i >= 200 || (i & 0x1f) == 0) && clk::now() >= deadline) {
			ok = wm.load(std::memory_order_acquire) >= ts;
			break;
		}
	}
	m_waits.fetch_add(1, std::memory_order_relaxed);
	m_wait_ns.fetch_add(
	        std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now() - start).count(),
	        std::memory_order_relaxed);
	if(!ok) {
		m_timeouts.fetch_add(1, std::memory_order_relaxed);
	}
	return ok;
}

sinsp_ctx_sync::stats sinsp_ctx_sync::get_stats() const {
	return {m_waits.load(std::memory_order_relaxed),
	        m_timeouts.load(std::memory_order_relaxed),
	        m_wait_ns.load(std::memory_order_relaxed)};
}

void sinsp_ctx_sync::reset_stats() {
	m_waits = 0;
	m_timeouts = 0;
	m_wait_ns = 0;
}
