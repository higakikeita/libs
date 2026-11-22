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
// handled first, and the copy taken at the clone exit contains an fd the child never had.
TEST_F(multi_buffer_order, DISABLED_fd_opened_after_clone_is_not_inherited_when_the_open_is_early) {
	child_is_created(CHILD_TID, PARENT_TID);
	thread_opens_a_file(PARENT_TID, PARENT_FD);

	process_next_in_buffer_of(PARENT_TID);
	process_next_in_buffer_of(CHILD_TID);
	EXPECT_FALSE(child_has_fd(PARENT_FD))
	        << "the child has an fd that the parent opened after the clone";
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
