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
 * Tests for the multi-buffer (multi-worker) mode of the inspector.
 *
 * In this mode the modern BPF probe routes the events to the ring buffers by TGID, and each buffer
 * is consumed by its own worker. The events of a thread group are processed in order by a single
 * worker, but nothing orders the events of different thread groups: when a process is created, the
 * worker of the child handles the clone exit and needs the state of the parent, which belongs to
 * another worker that can be ahead or behind.
 *
 * These tests drive the buffers one at a time, from a single thread, in an order chosen by the
 * test, so that an interleaving that can happen in production is reproduced deterministically. The
 * events are created in the order in which they happened (the timestamps increase with every call),
 * and then processed in a different order.
 *
 * The tests whose name starts with DISABLED_ describe known limits of the design (see the multi
 * thread proposal of Falco, "Cross-Partition Temporal Inconsistency"): they fail today.
 */

#include <sinsp_with_test_input.h>

#include <functional>

namespace {
constexpr int64_t PARENT_TID = INIT_TID;  // the init thread
constexpr int64_t CHILD_TID = 100;
constexpr int64_t PARENT_FD = 4;

class multi_buffer_order : public sinsp_with_test_input {
protected:
	void SetUp() override {
		add_default_init_thread();
		open_inspector_multi_buffer(2);
	}

	// From now on the events created by the generate_*() helpers go to the buffer of `tgid`, like
	// the probe does, and are not processed.
	void emit_in_buffer_of(int64_t tgid) { route_to_buffer(buffer_for_tgid(tgid)); }

	// Processes the next event of the buffer of `tgid`.
	void process_next_in_buffer_of(int64_t tgid) {
		route_to_buffer(-1);
		ASSERT_NE(next_event_from_buffer(buffer_for_tgid(tgid)), nullptr);
	}

	// The clone exit as seen by the caller (the parent): its worker captures the state the child
	// inherits. The kernel emits it in the buffer of the parent, in order with its other events.
	void parent_clone_returns(int64_t child_tid, int64_t parent_tid, uint32_t flags = 0) {
		emit_in_buffer_of(parent_tid);
		generate_clone_x_event(child_tid, parent_tid, parent_tid, 0, flags);
	}

	void set_handoff(const std::function<void(sinsp_ctx_sync::config&)>& fn) {
		auto cfg = m_inspector.get_ctx_sync().get_config();
		fn(cfg);
		m_inspector.get_ctx_sync().set_config(cfg);
	}

	// The clone exit as seen by the child: it is the event that creates the thread.
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
};
}  // namespace

// Control: the buffers of the parent and of the child are two different ones.
TEST_F(multi_buffer_order, parent_and_child_use_different_buffers) {
	ASSERT_NE(buffer_for_tgid(PARENT_TID), buffer_for_tgid(CHILD_TID));
}

// --- fd table inheritance -----------------------------------------------------------------------
//
// A new process starts with a copy of the fd table of its parent. The copy is taken from the live
// table of the parent when the worker of the child handles the clone exit, and nothing makes it
// wait for the worker of the parent.

// Control: the parent opens a file, then the child is created, and the events are processed in this
// order.
TEST_F(multi_buffer_order, fd_opened_before_clone_is_inherited_in_order) {
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	child_is_created(CHILD_TID, PARENT_TID);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_TRUE(child_has_fd(PARENT_FD));
}

// The parent opened the file before the clone, but the worker of the parent is behind: the clone
// exit of the child is handled first and the copy misses the fd.
TEST_F(multi_buffer_order, DISABLED_fd_opened_before_clone_is_inherited_when_the_open_is_late) {
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	child_is_created(CHILD_TID, PARENT_TID);

	process_next_in_buffer_of(CHILD_TID);
	process_next_in_buffer_of(PARENT_TID);
	EXPECT_TRUE(child_has_fd(PARENT_FD))
	        << "the fd the parent opened before the clone is missing in the child";
}

// Control: the child is created, then the parent opens a file.
TEST_F(multi_buffer_order, fd_opened_after_clone_is_not_inherited_in_order) {
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(CHILD_TID);
	process_next_in_buffer_of(PARENT_TID);
	EXPECT_FALSE(child_has_fd(PARENT_FD));
}

// The parent opens a file after the clone, but the worker of the parent is ahead: the open is
// handled first. The worker of the parent captured the state of the child at its own clone exit,
// so the child does not get the fd (fork snapshot handoff).
TEST_F(multi_buffer_order, fd_opened_after_clone_is_not_inherited_when_the_open_is_early) {
	parent_clone_returns(CHILD_TID, PARENT_TID);
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(PARENT_TID);  // the clone exit of the caller: the snapshot
	process_next_in_buffer_of(PARENT_TID);  // the open
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_FALSE(child_has_fd(PARENT_FD))
	        << "the child has an fd that the parent opened after the clone";
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.put, 1u);
	EXPECT_EQ(st.consumed, 1u);
	EXPECT_EQ(st.pending, 0u);
}

// Same, but the child's event is older than the one of the caller (the child ran first).
TEST_F(multi_buffer_order, fd_opened_after_clone_is_not_inherited_when_the_child_event_is_older) {
	child_is_created(CHILD_TID, PARENT_TID);
	parent_clone_returns(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_FALSE(child_has_fd(PARENT_FD));
}

// The fd opened before the clone is in the snapshot even if the child is handled much later.
TEST_F(multi_buffer_order, fd_opened_before_clone_is_inherited_through_the_snapshot) {
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	parent_clone_returns(CHILD_TID, PARENT_TID);
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD + 1);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_TRUE(child_has_fd(PARENT_FD));
	EXPECT_FALSE(child_has_fd(PARENT_FD + 1));
}

// The clone exit of the caller was lost (or is not processed yet): the child falls back to the live
// state of the parent, which is the behavior without the handoff. Here the parent is ahead, so the
// late fd shows up: this is the known limit that remains when the caller event is missing.
TEST_F(multi_buffer_order, without_the_caller_event_the_child_copies_the_live_parent) {
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_TRUE(child_has_fd(PARENT_FD));
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.consumed, 0u);
	EXPECT_EQ(st.live_copies, 1u);
}

// The child is handled first (the parent's worker is behind) and copies the live parent; the late
// caller event then does not publish anything and does not leave anything behind.
TEST_F(multi_buffer_order, a_late_caller_event_leaves_nothing_behind) {
	parent_clone_returns(CHILD_TID, PARENT_TID);
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(CHILD_TID);
	process_next_in_buffer_of(PARENT_TID);  // the clone exit of the caller
	process_next_in_buffer_of(PARENT_TID);  // the open
	EXPECT_FALSE(child_has_fd(PARENT_FD));  // the live parent had not opened it yet
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.live_copies, 1u);
	EXPECT_EQ(st.skipped_puts, 1u);
	EXPECT_EQ(st.put, 0u);
	EXPECT_EQ(st.pending, 0u);
}

// --- thread clones ------------------------------------------------------------------------------
//
// A new thread shares the fd table of its process: there is nothing to hand over, and an fd opened
// after the clone is visible from the new thread.
TEST_F(multi_buffer_order, a_thread_clone_shares_the_fd_table_and_takes_no_snapshot) {
	constexpr int64_t THREAD_TID = 102;
	parent_clone_returns(THREAD_TID, PARENT_TID, PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES);
	emit_in_buffer_of(PARENT_TID);  // a thread belongs to the buffer of its process
	generate_clone_x_event(0,
	                       THREAD_TID,
	                       PARENT_TID,
	                       0,
	                       PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(PARENT_TID);
	auto thread = m_inspector.m_thread_manager->find_thread(THREAD_TID, true);
	ASSERT_NE(thread, nullptr);
	EXPECT_NE(thread->get_fd(PARENT_FD), nullptr) << "the thread shares the table of the process";
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.put, 0u);
	EXPECT_EQ(st.live_copies, 0u);
	EXPECT_EQ(st.pending, 0u);
}

// --- bounded memory, tid reuse ------------------------------------------------------------------

// Snapshots that are never consumed (the event of the child was lost): the size is bounded.
TEST_F(multi_buffer_order, unconsumed_snapshots_are_bounded_by_size) {
	set_handoff([](auto& cfg) { cfg.handoff_max_entries = 32; });  // 2 per shard
	constexpr int N = 200;
	for(int i = 0; i < N; i++) {
		parent_clone_returns(1000 + i, PARENT_TID);
	}
	for(int i = 0; i < N; i++) {
		process_next_in_buffer_of(PARENT_TID);
	}
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.put, static_cast<uint64_t>(N));
	EXPECT_LE(st.pending, 32u);
	EXPECT_GE(st.dropped, static_cast<uint64_t>(N) - 32);
}

// ... and by age: the child tids are all in the same shard, one snapshot every 10 ms of event time.
TEST_F(multi_buffer_order, unconsumed_snapshots_expire) {
	set_handoff([](auto& cfg) { cfg.handoff_ttl_ns = 50'000'000; });
	constexpr int N = 40;
	for(int i = 0; i < N; i++) {
		parent_clone_returns(1600 + 16 * i, PARENT_TID);
	}
	for(int i = 0; i < N; i++) {
		process_next_in_buffer_of(PARENT_TID);
	}
	const auto st = m_inspector.get_ctx_sync().get_handoff_stats();
	EXPECT_EQ(st.put, static_cast<uint64_t>(N));
	EXPECT_LE(st.pending, 7u);
}

// A snapshot of another parent for the same tid (the tid was reused) is never used.
TEST_F(multi_buffer_order, a_snapshot_of_another_parent_is_not_used_when_the_tid_is_reused) {
	constexpr int64_t OTHER_PARENT = 101;  // same buffer as the init thread, not as the child
	child_is_created(OTHER_PARENT, PARENT_TID);
	process_next_in_buffer_of(OTHER_PARENT);

	thread_opens_a_file(PARENT_TID, PARENT_FD);       // only the init thread has this fd
	parent_clone_returns(CHILD_TID, PARENT_TID);      // snapshot of the init thread: never consumed
	thread_opens_a_file(OTHER_PARENT, PARENT_FD + 5);  // only the other parent has this fd
	parent_clone_returns(CHILD_TID, OTHER_PARENT);     // the tid is reused by another parent
	child_is_created(CHILD_TID, OTHER_PARENT);
	for(int i = 0; i < 4; i++) {
		process_next_in_buffer_of(PARENT_TID);
	}
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_FALSE(child_has_fd(PARENT_FD));
	EXPECT_TRUE(child_has_fd(PARENT_FD + 5));
}

// A snapshot of the same parent that is too old for the clone of the child is not used either.
TEST_F(multi_buffer_order, an_old_snapshot_is_not_used_when_the_tid_is_reused) {
	set_handoff([](auto& cfg) { cfg.handoff_match_ns = 15'000'000; });
	parent_clone_returns(CHILD_TID, PARENT_TID);  // snapshot without PARENT_FD, never consumed
	thread_opens_a_file(PARENT_TID, PARENT_FD);
	for(int i = 0; i < 5; i++) {
		emit_in_buffer_of(PARENT_TID);  // time goes by, in the buffer of the parent
		generate_random_event(PARENT_TID);
	}
	child_is_created(CHILD_TID, PARENT_TID);  // the caller event of this clone was lost
	for(int i = 0; i < 7; i++) {
		process_next_in_buffer_of(PARENT_TID);
	}
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_TRUE(child_has_fd(PARENT_FD)) << "the old snapshot was used instead of the live parent";
}

// --- ancestor information -----------------------------------------------------------------------
//
// The rules read the process of the parent (proc.pname, proc.aname[N]...) while the event of the
// child is evaluated. The parent belongs to another worker, so the information can be old.

namespace {
constexpr int64_t GRANDCHILD_TID = 101;  // a child of CHILD_TID, in the buffer of the init thread
}

// The parent was created, then it ran a new program, then it created a child, which did something.
// Control: everything is processed in the order in which it happened.
TEST_F(multi_buffer_order, ancestor_name_after_exec_in_order) {
	child_is_created(CHILD_TID, PARENT_TID);
	emit_in_buffer_of(CHILD_TID);
	generate_execve_exit_event_with_default_params(CHILD_TID, "/tmp/evil", "evil");
	child_is_created(GRANDCHILD_TID, CHILD_TID);
	emit_in_buffer_of(GRANDCHILD_TID);
	generate_random_event(GRANDCHILD_TID);

	process_next_in_buffer_of(CHILD_TID);       // the parent is created
	process_next_in_buffer_of(CHILD_TID);       // the parent runs the new program
	process_next_in_buffer_of(GRANDCHILD_TID);  // the child is created
	route_to_buffer(-1);
	auto evt = next_event_from_buffer(buffer_for_tgid(GRANDCHILD_TID));
	ASSERT_NE(evt, nullptr);
	EXPECT_EQ(get_field_as_string(evt, "proc.pname"), "evil");
}

// The worker of the child is ahead of the worker of its parent: the event of the child is evaluated
// before the parent ran the new program, so the parent still has its old name. A rule that matches
// on the name of the parent would not fire.
TEST_F(multi_buffer_order, DISABLED_ancestor_name_after_exec_when_the_parent_is_behind) {
	child_is_created(CHILD_TID, PARENT_TID);
	emit_in_buffer_of(CHILD_TID);
	generate_execve_exit_event_with_default_params(CHILD_TID, "/tmp/evil", "evil");
	child_is_created(GRANDCHILD_TID, CHILD_TID);
	emit_in_buffer_of(GRANDCHILD_TID);
	generate_random_event(GRANDCHILD_TID);

	process_next_in_buffer_of(CHILD_TID);  // the parent is created
	// The parent's worker stops here. The exec of the parent is still queued.
	process_next_in_buffer_of(GRANDCHILD_TID);  // the child is created
	route_to_buffer(-1);
	auto evt = next_event_from_buffer(buffer_for_tgid(GRANDCHILD_TID));
	ASSERT_NE(evt, nullptr);
	EXPECT_EQ(get_field_as_string(evt, "proc.pname"), "evil")
	        << "the event was evaluated with the old name of the parent";
}
