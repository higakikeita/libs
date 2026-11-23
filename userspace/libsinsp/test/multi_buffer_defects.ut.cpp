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
 * Reproductions of defects of the multi-buffer mode found in the review of the multi thread
 * support. Each test is named after the defect (D2, D5, ...) and is disabled because it fails
 * today: it is meant to be enabled when the defect is fixed.
 *
 * Like multi_buffer_order.ut.cpp, the tests drive the buffers from a single thread, in the order
 * chosen by the test.
 */

#include <sinsp_with_test_input.h>

namespace {
constexpr int64_t PARENT_TID = INIT_TID;
constexpr int64_t REUSED_TID = 100;  // not in the buffer of the init thread
constexpr int64_t OTHER_PROCESS = 102;

class multi_buffer_defects : public sinsp_with_test_input {
protected:
	void SetUp() override {
		add_default_init_thread();
		open_inspector_multi_buffer(2);
		auto cfg = m_inspector.get_ctx_sync().get_config();
		cfg.timeout_ns = 50 * 1000000;  // the tests process the buffers out of order on purpose
		m_inspector.get_ctx_sync().set_config(cfg);
	}

	void emit_in_buffer_of(int64_t tgid) { route_to_buffer(buffer_for_tgid(tgid)); }

	void process_next_in_buffer_of(int64_t tgid) {
		route_to_buffer(-1);
		ASSERT_NE(next_event_from_buffer(buffer_for_tgid(tgid)), nullptr);
	}

	// A new process: the clone exit of the child is in the buffer of the child.
	void process_is_created(int64_t tid, int64_t parent_tid) {
		emit_in_buffer_of(tid);
		generate_clone_x_event(0, tid, tid, parent_tid);
	}

	// A new thread of `pid`: the caller and the child events are in the buffer of `pid`.
	void thread_is_created(int64_t tid, int64_t pid) {
		constexpr uint32_t flags = PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
		emit_in_buffer_of(pid);
		generate_clone_x_event(tid, pid, pid, 0, flags);
		generate_clone_x_event(0, tid, pid, 0, flags);
	}

	void thread_exits(int64_t tid, int64_t pid) {
		emit_in_buffer_of(pid);
		generate_proc_exit_event(tid, 0);
		// The removal runs when the worker handles the next event after the exit.
		generate_random_event(pid);
	}

	// Creates REUSED_TID as a thread of the init process, then queues its exit.
	void old_thread_is_created_and_exit_is_pending() {
		ASSERT_NE(buffer_for_tgid(PARENT_TID), buffer_for_tgid(REUSED_TID));
		thread_is_created(REUSED_TID, PARENT_TID);
		// The old thread is older than CLONE_STALE_TIME_NS when the tid is reused: otherwise the
		// clone of the new one is taken for the clone of the old one and nothing is replaced.
		m_test_timestamp += 3 * SECOND_TO_NS;
		thread_exits(REUSED_TID, PARENT_TID);
	}

	void drain_old_thread_creation() {
		process_next_in_buffer_of(PARENT_TID);  // caller
		process_next_in_buffer_of(PARENT_TID);  // child: REUSED_TID is a thread of init
		ASSERT_NE(m_inspector.m_thread_manager->find_thread(REUSED_TID, true), nullptr);
	}
};
}  // namespace

// Control of the D2 and D5 tests: the exit of the old thread is handled before the tid is reused.
TEST_F(multi_buffer_defects, a_reused_tid_survives_when_the_exit_is_handled_in_order) {
	old_thread_is_created_and_exit_is_pending();
	process_is_created(REUSED_TID, PARENT_TID);

	drain_old_thread_creation();
	process_next_in_buffer_of(PARENT_TID);  // the exit of the old thread
	process_next_in_buffer_of(PARENT_TID);  // the removal of the old thread
	process_next_in_buffer_of(REUSED_TID);  // the new process with the reused tid

	auto fresh = m_inspector.m_thread_manager->find_thread(REUSED_TID, true);
	ASSERT_NE(fresh, nullptr);
	EXPECT_FALSE(fresh->is_dead());
	EXPECT_NE(m_inspector.m_thread_manager->get_thread_group_info(REUSED_TID), nullptr);
}

// D2 (REVIEW-2853 sec. 6): the exit of a thread that was already replaced by a new thread with the
// same tid kills the new one. sinsp_parser::parse_thread_exit (parsers.cpp) uses the thread that
// reset() found by tid, and sinsp::next then removes it by tid (sinsp.cpp, "procexit verdict"
// block, and sinsp_thread_manager::remove_thread). Nothing compares the identity of the thread
// or the age of the exit event. Here the tid of a non-leader thread of the init process is reused
// by a new process, whose events are in another buffer: the stale exit is handled last.
TEST_F(multi_buffer_defects, DISABLED_D2_stale_exit_of_a_reused_tid_does_not_kill_the_new_process) {
	old_thread_is_created_and_exit_is_pending();
	process_is_created(REUSED_TID, PARENT_TID);

	drain_old_thread_creation();
	process_next_in_buffer_of(REUSED_TID);  // the new process with the reused tid
	auto fresh = m_inspector.m_thread_manager->find_thread(REUSED_TID, true);
	ASSERT_NE(fresh, nullptr);
	ASSERT_FALSE(fresh->is_dead());

	process_next_in_buffer_of(PARENT_TID);  // the stale exit of the old thread
	process_next_in_buffer_of(PARENT_TID);  // the next event: the removal of the exited thread

	fresh = m_inspector.m_thread_manager->find_thread(REUSED_TID, true);
	ASSERT_NE(fresh, nullptr) << "the new process was removed by the exit of the old thread";
	EXPECT_FALSE(fresh->is_dead()) << "the new process was marked dead by the old exit";
}

// D2, second form: the tid is reused as a thread of another process (another buffer).
TEST_F(multi_buffer_defects, DISABLED_D2_stale_exit_of_a_reused_tid_does_not_kill_the_new_thread) {
	ASSERT_NE(buffer_for_tgid(PARENT_TID), buffer_for_tgid(OTHER_PROCESS));
	process_is_created(OTHER_PROCESS, PARENT_TID);
	old_thread_is_created_and_exit_is_pending();
	thread_is_created(REUSED_TID, OTHER_PROCESS);

	process_next_in_buffer_of(OTHER_PROCESS);  // the process that will own the new thread
	drain_old_thread_creation();
	process_next_in_buffer_of(OTHER_PROCESS);  // caller
	process_next_in_buffer_of(OTHER_PROCESS);  // child: REUSED_TID is now a thread of 102
	auto fresh = m_inspector.m_thread_manager->find_thread(REUSED_TID, true);
	ASSERT_NE(fresh, nullptr);
	ASSERT_EQ(fresh->get_pid(), OTHER_PROCESS);

	process_next_in_buffer_of(PARENT_TID);  // the stale exit of the old thread
	process_next_in_buffer_of(PARENT_TID);  // the next event: the removal of the exited thread

	fresh = m_inspector.m_thread_manager->find_thread(REUSED_TID, true);
	ASSERT_NE(fresh, nullptr) << "the new thread was removed by the exit of the old thread";
	EXPECT_FALSE(fresh->is_dead()) << "the new thread was marked dead by the old exit";
	auto group = m_inspector.m_thread_manager->get_thread_group_info(OTHER_PROCESS);
	ASSERT_NE(group, nullptr);
	EXPECT_EQ(group->get_thread_count(), 2u) << "the alive count of the group was decremented";
}

// D5 (REVIEW-2853 sec. 6): the removal erases the thread group and the leader by pid, without
// checking that they are the ones of the thread being removed (sinsp_thread_manager::remove_thread:
// m_thread_groups.erase(pid), m_threadtable.erase(pid)). When the stale exit of D2 reaches a
// process that reused the tid, the group of the new process is erased.
TEST_F(multi_buffer_defects, DISABLED_D5_stale_exit_of_a_reused_pid_does_not_erase_the_new_group) {
	old_thread_is_created_and_exit_is_pending();
	process_is_created(REUSED_TID, PARENT_TID);

	drain_old_thread_creation();
	process_next_in_buffer_of(REUSED_TID);
	ASSERT_NE(m_inspector.m_thread_manager->get_thread_group_info(REUSED_TID), nullptr);

	process_next_in_buffer_of(PARENT_TID);  // the stale exit of the old thread
	process_next_in_buffer_of(PARENT_TID);  // the next event: the removal of the exited thread

	EXPECT_NE(m_inspector.m_thread_manager->get_thread_group_info(REUSED_TID), nullptr)
	        << "the group of the new process was erased";
}
