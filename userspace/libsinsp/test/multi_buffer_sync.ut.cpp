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

/*
 * Tests of the cross-partition context synchronization (sinsp_ctx_sync) of the multi-worker mode.
 *
 * The scenarios of multi_buffer_order.ut.cpp, but with one real thread per buffer consuming
 * pre-filled buffers with sinsp::next(). The adversarial schedule is produced by delaying one of
 * the workers (sleep): the assertions are about the outcome, never about the duration.
 *
 * The idle watermark needs a clock in the domain of the event timestamps: the test events live in
 * 2019, so the tests install a clock that is far in the future.
 */

#include <sinsp_with_test_input.h>

#include <malloc.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>

namespace {
constexpr int64_t PARENT_TID = INIT_TID;
constexpr int64_t CHILD_TID = 100;
constexpr int64_t GRANDCHILD_TID = 101;
constexpr int64_t PARENT_FD = 4;
constexpr int REPETITIONS = 200;

class multi_buffer_sync : public sinsp_with_test_input {
protected:
	void SetUp() override {
		add_default_init_thread();
		open_inspector_multi_buffer(2);
		// Far in the future with respect to the events (the test timestamps start in 2019).
		m_inspector.get_ctx_sync().set_clock([] { return UINT64_C(4000000000000000000); });
		set_timeout_ms(5000);  // generous: a wait that times out is a failure of the tests below
	}

	void set_timeout_ms(uint64_t ms) {
		auto cfg = m_inspector.get_ctx_sync().get_config();
		cfg.timeout_ns = ms * 1000000;
		m_inspector.get_ctx_sync().set_config(cfg);
	}

	void emit_in_buffer_of(int64_t tgid) { route_to_buffer(buffer_for_tgid(tgid)); }

	// The clone exit of the caller, in the buffer of the parent (see the fork snapshot handoff).
	void parent_clone_returns(int64_t child_tid, int64_t parent_tid) {
		emit_in_buffer_of(parent_tid);
		generate_clone_x_event(child_tid, parent_tid, parent_tid, 0);
	}

	void child_is_created(int64_t child_tid, int64_t parent_tid) {
		emit_in_buffer_of(child_tid);
		generate_clone_x_event(0, child_tid, child_tid, parent_tid);
	}

	void thread_opens_a_file(int64_t tid, int64_t fd) {
		emit_in_buffer_of(tid);
		sinsp_test_input::open_params params;
		params.fd = fd;
		generate_open_x_event(params, tid);
	}

	bool child_has_fd(int64_t fd) {
		auto child = m_inspector.m_thread_manager->find_thread(CHILD_TID, true);
		return child != nullptr && child->get_fd(fd) != nullptr;
	}

	// Per-event callback of the workers: (buffer index, event, index of the event in the buffer).
	using on_event_fn = std::function<void(uint16_t, sinsp_evt*, size_t)>;

	// One thread per buffer consumes the whole buffer with sinsp::next(). `start_delay_ms[i]` delays
	// the first call of the worker of buffer i, `never_start[i]` keeps it from running at all. When
	// a worker has consumed its events it keeps polling the (empty) buffer, like a real worker,
	// until every other worker is done, so that the idle watermark is published.
	void run_workers(const std::vector<int>& start_delay_ms,
	                 const std::vector<bool>& never_start = {},
	                 const on_event_fn& on_event = nullptr) {
		route_to_buffer(-1);
		const uint16_t n = static_cast<uint16_t>(m_buffer_events.size());
		std::atomic<int> workers_running{0};
		std::atomic<bool> all_done{false};
		std::vector<std::thread> threads;
		for(uint16_t i = 0; i < n; i++) {
			if(i < never_start.size() && never_start[i]) {
				continue;
			}
			workers_running++;
			threads.emplace_back([&, i] {
				std::this_thread::sleep_for(std::chrono::milliseconds(start_delay_ms[i]));
				const size_t expected = m_buffer_events[i].size();
				size_t consumed = 0;
				bool finished = false;
				while(!all_done.load(std::memory_order_acquire)) {
					sinsp_evt* evt = nullptr;
					const int32_t res = m_inspector.next(&evt, static_cast<sinsp_buffer_t>(i + 1));
					if(res == SCAP_SUCCESS || res == SCAP_FILTERED_EVENT) {
						if(on_event && res == SCAP_SUCCESS) {
							on_event(i, evt, consumed);
						}
						consumed++;
					} else {
						std::this_thread::sleep_for(std::chrono::microseconds(100));
					}
					if(!finished && consumed == expected) {
						finished = true;
						workers_running--;
					}
				}
			});
		}
		while(workers_running.load() > 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		all_done = true;
		for(auto& t : threads) {
			t.join();
		}
	}
};

class multi_buffer_sync_repeat : public multi_buffer_sync, public ::testing::WithParamInterface<int> {
};
}  // namespace

// --- the three scenarios of multi_buffer_order.ut.cpp, with real workers -------------------------

// The parent opened the file before the clone but its worker is late: the child's worker waits for
// it, and the child inherits the fd.
TEST_P(multi_buffer_sync_repeat, fd_opened_before_clone_is_inherited_when_the_parent_worker_is_late) {
	ASSERT_NE(buffer_for_tgid(PARENT_TID), buffer_for_tgid(CHILD_TID));
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	child_is_created(CHILD_TID, PARENT_TID);

	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(PARENT_TID)] = 5;
	run_workers(delay);

	EXPECT_TRUE(child_has_fd(PARENT_FD));
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u);
}

// The parent opens the file AFTER the clone, and its worker is ahead of the one of the child. The
// watermark wait cannot undo what the parent already did: the worker of the parent captures the
// state of the child at its own clone exit (fork snapshot handoff), and the child uses it. This is
// the threaded twin of fd_opened_after_clone_is_not_inherited_when_the_open_is_early in
// multi_buffer_order.ut.cpp.
TEST_P(multi_buffer_sync_repeat,
       fd_opened_after_clone_is_not_inherited_when_the_parent_worker_is_ahead) {
	parent_clone_returns(CHILD_TID, PARENT_TID);
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(CHILD_TID)] = 5;
	run_workers(delay);

	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_FALSE(child_has_fd(PARENT_FD))
	        << "the child has an fd that the parent opened after the clone (put=" << st.put
	        << " consumed=" << st.consumed << " live=" << st.live_copies
	        << " skipped=" << st.skipped_puts << " dropped=" << st.dropped << ")";
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u);
	EXPECT_EQ(st.pending, 0u);
}

// Every start schedule (the parameter selects one of the 8 combinations), and the child event
// older or newer than the one of the caller: the open after the clone must never be in the child,
// the open before the clone always.
TEST_P(multi_buffer_sync_repeat, the_snapshot_is_exact_for_every_schedule) {
	const bool child_event_first = (GetParam() & 1) != 0;
	const int parent_delay = (GetParam() & 2) != 0 ? 3 : 0;
	const int child_delay = (GetParam() & 4) != 0 ? 3 : 0;
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	if(child_event_first) {
		child_is_created(CHILD_TID, PARENT_TID);
		parent_clone_returns(CHILD_TID, PARENT_TID);
	} else {
		parent_clone_returns(CHILD_TID, PARENT_TID);
		child_is_created(CHILD_TID, PARENT_TID);
	}
	thread_opens_a_file(PARENT_TID, PARENT_FD + 1);

	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(PARENT_TID)] = parent_delay;
	delay[buffer_for_tgid(CHILD_TID)] = child_delay;
	run_workers(delay);

	const std::string what = std::string("child_event_first=") + (child_event_first ? "1" : "0") +
	                         " parent_delay=" + std::to_string(parent_delay) +
	                         " child_delay=" + std::to_string(child_delay);
	EXPECT_TRUE(child_has_fd(PARENT_FD)) << what;
	EXPECT_FALSE(child_has_fd(PARENT_FD + 1)) << what;
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u) << what;
}

// Same as above, with the clone exit of the caller: the late parent's worker takes the snapshot.
TEST_P(multi_buffer_sync_repeat,
       fd_opened_before_clone_is_inherited_when_the_parent_worker_is_late_with_the_caller_event) {
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	parent_clone_returns(CHILD_TID, PARENT_TID);
	child_is_created(CHILD_TID, PARENT_TID);

	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(PARENT_TID)] = 5;
	run_workers(delay);

	EXPECT_TRUE(child_has_fd(PARENT_FD));
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u);
}

// The child of a parent whose worker is late sees the new name of the parent (proc.pname).
TEST_P(multi_buffer_sync_repeat, ancestor_name_is_up_to_date_when_the_parent_worker_is_late) {
	child_is_created(CHILD_TID, PARENT_TID);
	emit_in_buffer_of(CHILD_TID);
	generate_execve_exit_event_with_default_params(CHILD_TID, "/tmp/evil", "evil");
	child_is_created(GRANDCHILD_TID, CHILD_TID);
	emit_in_buffer_of(GRANDCHILD_TID);
	generate_random_event(GRANDCHILD_TID);

	std::string pname;
	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(CHILD_TID)] = 5;
	run_workers(delay, {}, [&](uint16_t buffer, sinsp_evt* evt, size_t index) {
		// The second event of the buffer of the grandchild: the clone exit is the first.
		if(buffer == buffer_for_tgid(GRANDCHILD_TID) && index == 1) {
			pname = get_field_as_string(evt, "proc.pname");
		}
	});

	EXPECT_EQ(pname, "evil") << "the event was evaluated with the old name of the parent";
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u);
}

// The grandchild is created BEFORE the parent runs the new program, and then does something. The
// clone exit of the grandchild is not enough: the rule evaluation of the event of the grandchild
// reads the parent, so it must wait for the partition of the parent (proc.pname, evaluation time).
TEST_P(multi_buffer_sync_repeat, ancestor_name_read_at_evaluation_waits_for_the_parent_worker) {
	child_is_created(CHILD_TID, PARENT_TID);
	child_is_created(GRANDCHILD_TID, CHILD_TID);
	emit_in_buffer_of(CHILD_TID);
	generate_execve_exit_event_with_default_params(CHILD_TID, "/tmp/evil", "evil");
	emit_in_buffer_of(GRANDCHILD_TID);
	generate_random_event(GRANDCHILD_TID);

	std::string pname;
	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(CHILD_TID)] = 5;
	run_workers(delay, {}, [&](uint16_t buffer, sinsp_evt* evt, size_t index) {
		// The second event of the buffer of the grandchild: the clone exit is the first.
		if(buffer == buffer_for_tgid(GRANDCHILD_TID) && index == 1) {
			pname = get_field_as_string(evt, "proc.pname");
		}
	});

	EXPECT_EQ(pname, "evil");
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().timeouts, 0u);
}

INSTANTIATE_TEST_SUITE_P(repeat, multi_buffer_sync_repeat, ::testing::Range(0, REPETITIONS));

// --- controls and limits ------------------------------------------------------------------------

// Control: without the synchronization, the same schedule loses the fd. It shows that the
// scenario above is adversarial and that the wait is what fixes it.
TEST_F(multi_buffer_sync, without_the_wait_the_late_open_is_lost) {
	auto cfg = m_inspector.get_ctx_sync().get_config();
	cfg.enabled = false;
	m_inspector.get_ctx_sync().set_config(cfg);

	thread_opens_a_file(PARENT_TID, PARENT_FD);
	child_is_created(CHILD_TID, PARENT_TID);

	std::vector<int> delay(2, 0);
	delay[buffer_for_tgid(PARENT_TID)] = 200;
	run_workers(delay);

	EXPECT_FALSE(child_has_fd(PARENT_FD));
}

// The parent worker never advances: the wait times out, the behavior is the one without the wait,
// and the timeout is counted.
TEST_F(multi_buffer_sync, a_parent_worker_that_never_advances_times_out) {
	set_timeout_ms(30);
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	child_is_created(CHILD_TID, PARENT_TID);

	std::vector<bool> never(2, false);
	never[buffer_for_tgid(PARENT_TID)] = true;
	run_workers({0, 0}, never);

	const auto stats = m_inspector.get_ctx_sync().get_stats();
	EXPECT_EQ(stats.timeouts, 1u);
	EXPECT_EQ(stats.waits, 1u);
	EXPECT_TRUE(m_inspector.m_thread_manager->find_thread(CHILD_TID, true) != nullptr)
	        << "the child must be created even if the wait timed out";
	EXPECT_FALSE(child_has_fd(PARENT_FD)) << "fallback: the state of the parent was not ready";
}

// A parent that is already ahead: no wait at all.
TEST_F(multi_buffer_sync, no_wait_when_the_parent_worker_is_ahead) {
	child_is_created(CHILD_TID, PARENT_TID);
	route_to_buffer(-1);

	// Make the parent's partition publish a watermark that is beyond the clone.
	m_inspector.get_ctx_sync().publish_idle(buffer_for_tgid(PARENT_TID), UINT64_C(4000000000000000000));
	ASSERT_NE(next_event_from_buffer(buffer_for_tgid(CHILD_TID)), nullptr);

	const auto stats = m_inspector.get_ctx_sync().get_stats();
	EXPECT_EQ(stats.waits, 0u);
	EXPECT_EQ(stats.timeouts, 0u);
}

// Parent and child in the same buffer: a worker never waits for itself.
class multi_buffer_sync_one_buffer : public sinsp_with_test_input {
protected:
	void SetUp() override {
		add_default_init_thread();
		open_inspector_multi_buffer(1);  // every thread group is in buffer 0
	}
};

TEST_F(multi_buffer_sync_one_buffer, never_waits_on_its_own_buffer) {
	ASSERT_EQ(buffer_for_tgid(PARENT_TID), buffer_for_tgid(CHILD_TID));

	route_to_buffer(0);
	sinsp_test_input::open_params params;
	params.fd = PARENT_FD;
	generate_open_x_event(params, PARENT_TID);
	generate_clone_x_event(0, CHILD_TID, CHILD_TID, PARENT_TID);
	route_to_buffer(-1);
	ASSERT_NE(next_event_from_buffer(0), nullptr);
	ASSERT_NE(next_event_from_buffer(0), nullptr);

	auto child = m_inspector.m_thread_manager->find_thread(CHILD_TID, true);
	ASSERT_NE(child, nullptr);
	EXPECT_NE(child->get_fd(PARENT_FD), nullptr);
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().waits, 0u);
}

// The parent is not in the thread table and, guessing that it is the leader of its group, it lives
// in the buffer of the child: no wait.
TEST_F(multi_buffer_sync, no_wait_when_the_unknown_parent_is_in_the_own_buffer) {
	child_is_created(CHILD_TID, /*parent_tid=*/4242);  // 4242 and CHILD_TID: same buffer
	ASSERT_EQ(buffer_for_tgid(4242), buffer_for_tgid(CHILD_TID));
	route_to_buffer(-1);
	ASSERT_NE(next_event_from_buffer(buffer_for_tgid(CHILD_TID)), nullptr);
	EXPECT_EQ(m_inspector.get_ctx_sync().get_stats().waits, 0u);
}

// The parent is not in the table, for example because the worker that creates it is behind: the
// worker of the child waits for the buffer where the parent would be. Here nobody advances it, so
// the wait times out and the child is created anyway.
TEST_F(multi_buffer_sync, an_unknown_parent_in_another_buffer_is_waited_for_with_a_timeout) {
	set_timeout_ms(20);
	child_is_created(CHILD_TID, /*parent_tid=*/4243);
	ASSERT_NE(buffer_for_tgid(4243), buffer_for_tgid(CHILD_TID));
	route_to_buffer(-1);
	ASSERT_NE(next_event_from_buffer(buffer_for_tgid(CHILD_TID)), nullptr);
	const auto stats = m_inspector.get_ctx_sync().get_stats();
	EXPECT_EQ(stats.waits, 1u);
	EXPECT_EQ(stats.timeouts, 1u);
	EXPECT_NE(m_inspector.m_thread_manager->find_thread(CHILD_TID, true), nullptr);
}

// Single-thread mode (a single event stream): the synchronization does not exist.
class single_thread_sync : public sinsp_with_test_input {};

TEST_F(single_thread_sync, no_waiting_in_single_thread_mode) {
	add_default_init_thread();
	open_inspector();

	EXPECT_EQ(m_inspector.get_ctx_sync().n_buffers(), 0u);
	EXPECT_FALSE(m_inspector.get_ctx_sync().enabled());

	generate_clone_x_event(0, CHILD_TID, CHILD_TID, PARENT_TID);
	auto stats = m_inspector.get_ctx_sync().get_stats();
	EXPECT_EQ(stats.waits, 0u);
	EXPECT_EQ(stats.timeouts, 0u);
	EXPECT_NE(m_inspector.m_thread_manager->find_thread(CHILD_TID, true), nullptr);
}

// The fork snapshot handoff does not exist either: the caller creates the child, as before.
TEST_F(single_thread_sync, no_snapshot_in_single_thread_mode) {
	add_default_init_thread();
	open_inspector();

	sinsp_test_input::open_params params;
	params.fd = PARENT_FD;
	generate_open_x_event(params, PARENT_TID);
	generate_clone_x_event(CHILD_TID, PARENT_TID, PARENT_TID, 0);  // the caller
	auto child = m_inspector.m_thread_manager->find_thread(CHILD_TID, true);
	ASSERT_NE(child, nullptr);
	EXPECT_NE(child->get_fd(PARENT_FD), nullptr);
	generate_clone_x_event(0, CHILD_TID, CHILD_TID, PARENT_TID);  // the child
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.put + st.consumed + st.live_copies + st.skipped_puts + st.dropped + st.pending,
	          0u);
}

// --- micro benchmarks (disabled: run with --gtest_also_run_disabled_tests --gtest_filter=*bench*) --
//
// Synthetic numbers, not real traffic. They only print; nothing is asserted about time.

namespace {
double now_ns() {
	return std::chrono::duration<double, std::nano>(
	               std::chrono::steady_clock::now().time_since_epoch())
	        .count();
}
}  // namespace

// Cost of the clone exit path when the parent's worker is already ahead (the common case): the
// same events are processed with the synchronization on and off. Single thread, so this measures
// the pure overhead of the check (a single acquire load), plus the clone exit itself.
TEST_F(multi_buffer_sync, DISABLED_bench_clone_exit_parent_ahead) {
	constexpr int ROUNDS = 5;
	constexpr int CLONES = 4000;
	// The parent's partition has published a watermark beyond everything.
	m_inspector.get_ctx_sync().publish_idle(buffer_for_tgid(PARENT_TID), UINT64_C(4000000000000000000));
	int64_t next_tid = 1000;  // even: the buffer of the child is not the one of the init thread
	double ns_on = 0, ns_off = 0;
	for(int round = 0; round < ROUNDS * 2; round++) {
		const bool on = (round % 2) == 0;
		auto cfg = m_inspector.get_ctx_sync().get_config();
		cfg.enabled = on;
		m_inspector.get_ctx_sync().set_config(cfg);
		for(int i = 0; i < CLONES; i++, next_tid += 2) {
			child_is_created(next_tid, PARENT_TID);
		}
		route_to_buffer(-1);
		const uint16_t b = buffer_for_tgid(1000);
		const double t0 = now_ns();
		for(int i = 0; i < CLONES; i++) {
			ASSERT_NE(next_event_from_buffer(b), nullptr);
		}
		(on ? ns_on : ns_off) += now_ns() - t0;
	}
	const double n = static_cast<double>(ROUNDS) * CLONES;
	printf("BENCH clone exit, parent ahead: sync on %.1f ns/clone, sync off %.1f ns/clone, "
	       "delta %.1f ns (waits=%lu)\n",
	       ns_on / n,
	       ns_off / n,
	       (ns_on - ns_off) / n,
	       static_cast<unsigned long>(m_inspector.get_ctx_sync().get_stats().waits));
}

// Latency added when the parent's partition is behind: a thread waits for a watermark that another
// thread publishes after `lag_us`. Reported: the time the waiter spent minus the lag.
TEST_F(multi_buffer_sync, DISABLED_bench_wait_latency_parent_behind) {
	auto& sync = m_inspector.get_ctx_sync();
	for(const int lag_us : {0, 20, 100, 1000, 3000}) {
		constexpr int N = 100;
		double sum_excess = 0, max_excess = 0;
		for(int i = 0; i < N; i++) {
			const uint64_t ts = UINT64_C(1000000000) * (lag_us + 1) + i + 1;
			std::atomic<double> published_at{0};
			std::thread publisher([&] {
				const double start = now_ns();
				while(now_ns() - start < lag_us * 1000.0) {
				}
				published_at = now_ns();
				sync.publish_event(1, ts);
			});
			sync.wait_for(0, 1, ts);
			const double done = now_ns();
			publisher.join();
			const double excess = done - published_at.load();
			sum_excess += excess;
			max_excess = std::max(max_excess, excess);
		}
		printf("BENCH wait latency, parent behind by %d us: wake-up delay after the publish "
		       "avg %.1f us, max %.1f us\n",
		       lag_us,
		       sum_excess / N / 1000.0,
		       max_excess / 1000.0);
	}
}

namespace {
// Bytes currently allocated from the heap (glibc), exact and not affected by the reuse of freed
// memory, unlike the resident set size.
size_t heap_in_use_bytes() {
	const auto info = mallinfo2();
	return info.uordblks + info.hblkhd;
}
}  // namespace

// Cost of the fork snapshot handoff for a burst of forks (a cron burst): `CLONES` processes are
// created by a parent that has `fds` open files. The caller events are processed in the buffer of
// the parent (the cost is paid there), then the child events in the buffer of the children. With
// the handoff off the caller event does nothing and the child copies the live parent.
TEST_F(multi_buffer_sync, DISABLED_bench_clone_snapshot_cost) {
	constexpr int CLONES = 1000;
	for(const int fds : {0, 16, 64, 256}) {
		for(int i = 0; i < fds; i++) {
			thread_opens_a_file(PARENT_TID, 100 + i);
		}
		route_to_buffer(-1);
		for(int i = 0; i < fds; i++) {
			ASSERT_NE(next_event_from_buffer(buffer_for_tgid(PARENT_TID)), nullptr);
		}
		m_inspector.get_ctx_sync().publish_idle(buffer_for_tgid(PARENT_TID),
		                                        UINT64_C(4000000000000000000));
		double ns_caller[2] = {0, 0}, ns_child[2] = {0, 0};
		for(const int on : {0, 1, 0, 1}) {  // interleaved, summed per mode
			auto cfg = m_inspector.get_ctx_sync().get_config();
			cfg.handoff_enabled = on != 0;
			cfg.handoff_max_entries = 1000000;
			cfg.handoff_ttl_ns = UINT64_C(1000000000000);
			m_inspector.get_ctx_sync().set_config(cfg);
			static int64_t next_tid = 100000;  // even: the child buffer is not the parent's
			const int64_t first = next_tid;
			for(int i = 0; i < CLONES; i++, next_tid += 2) {
				parent_clone_returns(next_tid, PARENT_TID);
				child_is_created(next_tid, PARENT_TID);
			}
			route_to_buffer(-1);
			double t0 = now_ns();
			for(int i = 0; i < CLONES; i++) {
				ASSERT_NE(next_event_from_buffer(buffer_for_tgid(PARENT_TID)), nullptr);
			}
			ns_caller[on] += now_ns() - t0;
			t0 = now_ns();
			for(int i = 0; i < CLONES; i++) {
				ASSERT_NE(next_event_from_buffer(buffer_for_tgid(first)), nullptr);
			}
			ns_child[on] += now_ns() - t0;
		}
		const double n = 2.0 * CLONES;
		printf("BENCH fork, parent with %3d fds: caller event off %.0f on %.0f ns; child event "
		       "off %.0f on %.0f ns; total off %.0f on %.0f ns/fork\n",
		       fds,
		       ns_caller[0] / n,
		       ns_caller[1] / n,
		       ns_child[0] / n,
		       ns_child[1] / n,
		       (ns_caller[0] + ns_child[0]) / n,
		       (ns_caller[1] + ns_child[1]) / n);
	}
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	printf("BENCH handoff stats: put=%lu consumed=%lu live=%lu skipped=%lu dropped=%lu "
	       "pending=%lu\n",
	       (unsigned long)st.put,
	       (unsigned long)st.consumed,
	       (unsigned long)st.live_copies,
	       (unsigned long)st.skipped_puts,
	       (unsigned long)st.dropped,
	       (unsigned long)st.pending);
}

// Memory held by snapshots that were published and never consumed.
TEST_F(multi_buffer_sync, DISABLED_bench_unconsumed_snapshot_memory) {
	constexpr int SNAPSHOTS = 1000;
	for(const int fds : {0, 16, 64, 256}) {
		auto cfg = m_inspector.get_ctx_sync().get_config();
		cfg.handoff_max_entries = 1000000;
		cfg.handoff_ttl_ns = UINT64_C(1000000000000);
		m_inspector.get_ctx_sync().set_config(cfg);
		for(int i = 0; i < fds; i++) {
			thread_opens_a_file(PARENT_TID, 100 + i);
		}
		static int64_t next_tid = 500000;
		for(int i = 0; i < SNAPSHOTS; i++, next_tid += 2) {
			parent_clone_returns(next_tid, PARENT_TID);
		}
		route_to_buffer(-1);
		for(int i = 0; i < fds; i++) {
			ASSERT_NE(next_event_from_buffer(buffer_for_tgid(PARENT_TID)), nullptr);
		}
		const size_t before = heap_in_use_bytes();
		const auto pending_before = m_inspector.get_ctx_sync().handoff_pending();
		for(int i = 0; i < SNAPSHOTS; i++) {
			ASSERT_NE(next_event_from_buffer(buffer_for_tgid(PARENT_TID)), nullptr);
		}
		const size_t after = heap_in_use_bytes();
		const auto held = m_inspector.get_ctx_sync().handoff_pending() - pending_before;
		printf("BENCH snapshots held: parent with %3d fds: %lu snapshots, heap +%.1f KB total, "
		       "%.0f bytes/snapshot\n",
		       fds,
		       (unsigned long)held,
		       (after - before) / 1024.0,
		       held ? static_cast<double>(after - before) / held : 0.0);
	}
}
