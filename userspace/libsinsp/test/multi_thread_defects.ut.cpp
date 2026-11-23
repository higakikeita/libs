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
 * Reproductions of defects of the multi thread support found in the review (see
 * multi_buffer_defects.ut.cpp for the ones that need several buffers). The tests named
 * DISABLED_D<n> fail today and are meant to be enabled when the defect is fixed.
 */

#include <sinsp_with_test_input.h>
#include <libsinsp/mpsc_priority_queue.h>
#include <libsinsp/state/dynamic_struct.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include <unistd.h>

namespace {
struct async_item {
	int ts;
	int payload;
};

struct async_item_cmp {
	// The same convention as the async events queue: the smallest timestamp first.
	bool operator()(const async_item& l, const async_item& r) const { return l.ts >= r.ts; }
};

using async_item_ptr = std::unique_ptr<async_item>;
using async_queue = mpsc_priority_queue<async_item_ptr, async_item_cmp>;
}  // namespace

// D1 (REVIEW-2853 sec. 6): mpsc_priority_queue is a single consumer queue, but sinsp::next calls
// try_pop_if() from every worker (sinsp.cpp, the async events queue). try_pop_if() checks that the
// queue is not empty only once, before its loop (mpsc_priority_queue.h), and then dereferences the
// top it loads. If another consumer pops the last element while the predicate runs, the loop
// goes around and dereferences a null top.
// The second consumer is run from inside the predicate, which is the interleaving point of the
// race, so that the schedule is deterministic. The body runs in a child process (death test)
// because the defect is a crash.
TEST(multi_thread_defects, DISABLED_D1_try_pop_if_with_a_second_consumer_on_the_last_element) {
	EXPECT_EXIT(
	        {
		        async_queue q;
		        q.push(async_item_ptr{new async_item{1, 1}});
		        async_item_ptr other;
		        bool stolen = false;
		        async_item_ptr res;
		        // This is the predicate of the first consumer.
		        const auto pred = [&](const async_item& item) {
			        // Reading the item through the reference is the access that crashes.
			        volatile int ts = item.ts;
			        (void)ts;
			        if(!stolen) {
				        stolen = true;
				        // The second consumer pops (and frees) the only element meanwhile.
				        q.try_pop(other);
				        other.reset();
			        }
			        return true;
		        };
		        q.try_pop_if(res, pred);
		        std::_Exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "")
	        << "the first consumer evaluated the predicate on an element that another consumer "
	           "had already popped (null/dangling top)";
}

// D1, with real threads: several consumers pop the elements of a queue that a producer fills.
// Every element must be delivered once. Run it under TSAN: the reads of the top element by a
// consumer race with the free done by the consumer that popped it.
TEST(multi_thread_defects, DISABLED_D1_concurrent_try_pop_if_delivers_every_element_once) {
	constexpr int N_CONSUMERS = 4;
	constexpr int N_ITEMS = 20000;
	EXPECT_EXIT(
	        {
		        async_queue q;
		        std::atomic<int> delivered{0};
		        std::atomic<int> sum{0};
		        std::atomic<bool> stop{false};
		        std::vector<std::thread> consumers;
		        for(int c = 0; c < N_CONSUMERS; c++) {
			        consumers.emplace_back([&] {
				        async_item_ptr res;
				        while(!stop.load()) {
					        if(!q.empty() &&
					           q.try_pop_if(res, [](const async_item& i) { return i.ts >= 0; })) {
						        sum += res->payload;
						        delivered++;
						        res.reset();
					        }
				        }
			        });
		        }
		        for(int i = 0; i < N_ITEMS; i++) {
			        q.push(async_item_ptr{new async_item{i, 1}});
		        }
		        for(int spin = 0; spin < 20000 && delivered.load() < N_ITEMS; spin++) {
			        std::this_thread::sleep_for(std::chrono::microseconds(100));
		        }
		        stop = true;
		        for(auto& t : consumers) {
			        t.join();
		        }
		        std::_Exit(delivered.load() == N_ITEMS && sum.load() == N_ITEMS ? 0 : 3);
	        },
	        ::testing::ExitedWithCode(0),
	        "")
	        << "elements were lost, duplicated, or the consumers crashed";
}

#ifdef LIBSINSP_USE_FOLLY
namespace {
class fd_cache_defects : public sinsp_with_test_input {};
}  // namespace

// D7 (REVIEW-2853 sec. 2.3 and 6): the fd lookup cache of the concurrent policy is thread local
// (fdtable.h tl_cache()) but erase()/add() invalidate only the cache of the calling thread
// (invalidate_tl_cache()). A thread that cached an fd keeps getting the old entry after another
// thread replaced or erased it, until it looks up another fd.
TEST_F(fd_cache_defects, DISABLED_D7_cached_fd_is_replaced_by_another_thread) {
	add_default_init_thread();
	open_inspector();
	sinsp_test_input::open_params params;
	params.fd = 5;
	params.path = "/old";
	generate_open_x_event(params);
	auto& table = m_inspector.m_thread_manager->find_thread(INIT_TID, true)->get_fdtable();
	ASSERT_NE(table.find(5), nullptr);

	std::atomic<int> step{0};
	std::string seen_after_replace;
	bool found_after_erase = true;
	std::thread reader([&] {
		ASSERT_EQ(table.find(5)->get_name(), "/old");  // fills the cache of this thread
		step = 1;
		while(step.load() != 2) {
			std::this_thread::yield();
		}
		auto fdi = table.find(5);
		seen_after_replace = fdi ? fdi->get_name() : "";
		step = 3;
		while(step.load() != 4) {
			std::this_thread::yield();
		}
		found_after_erase = table.find(5) != nullptr;
		step = 5;
	});
	while(step.load() != 1) {
		std::this_thread::yield();
	}
	table.erase(5);
	params.path = "/new";
	generate_open_x_event(params);
	step = 2;
	while(step.load() != 3) {
		std::this_thread::yield();
	}
	table.erase(5);
	step = 4;
	reader.join();

	EXPECT_EQ(seen_after_replace, "/new") << "the reader got the entry that was replaced";
	EXPECT_FALSE(found_after_erase) << "the reader found an entry that was erased";
}
#endif

namespace {
class thread_manager_defects : public sinsp_with_test_input {
protected:
	// A thread of the process `pid`, not added to the table yet.
	std::unique_ptr<sinsp_threadinfo> make_thread(int64_t tid, int64_t pid) {
		auto tinfo = m_inspector.get_threadinfo_factory().create();
		tinfo->m_tid = tid;
		tinfo->set_pid(pid);
		tinfo->set_ptid(INIT_TID);
		tinfo->set_comm("test");
		tinfo->set_exe("/bin/test");
		return tinfo;
	}
};

// Runs `fn(i)` on `n` threads that start together.
template<typename F>
void run_together(int n, F&& fn) {
	std::atomic<int> ready{0};
	std::atomic<bool> go{false};
	std::vector<std::thread> threads;
	for(int i = 0; i < n; i++) {
		threads.emplace_back([&, i] {
			ready++;
			while(!go.load()) {
			}
			fn(i);
		});
	}
	while(ready.load() < n) {
		std::this_thread::yield();
	}
	go = true;
	for(auto& t : threads) {
		t.join();
	}
}
}  // namespace

#ifdef LIBSINSP_USE_FOLLY
// D5 (REVIEW-2853 sec. 6): the creation of a thread group is a check-then-act
// (sinsp_thread_manager::create_thread_dependencies: get_thread_group_info(), then
// set_thread_group_info(), which replaces an existing entry). Threads of a new process added
// concurrently (a /proc lookup and the clone event, the purge...) can create two groups: some
// threads are then members of a group that is not the published one.
TEST_F(thread_manager_defects, DISABLED_D5_concurrent_adds_of_one_new_process_make_one_group) {
	add_default_init_thread();
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	constexpr int N = 8;
	constexpr int ROUNDS = 400;
	int split_membership = 0;  // a thread is not in the published group
	int wrong_count = 0;       // the group does not count N alive threads
	int wrong_list = 0;        // the group does not list N threads
	for(int round = 0; round < ROUNDS; round++) {
		const int64_t pid = 30000 + round * 16;
		run_together(N, [&](int i) { manager->add_thread(make_thread(pid + i, pid), true); });
		auto group = manager->get_thread_group_info(pid);
		ASSERT_NE(group, nullptr);
		wrong_count += group->get_thread_count() != N;
		wrong_list += group->get_thread_list().size() != N;
		bool split = false;
		for(int i = 0; i < N; i++) {
			auto t = manager->find_thread(pid + i, true);
			split = split || t == nullptr || t->get_tginfo() != group;
		}
		split_membership += split;
	}
	EXPECT_EQ(split_membership, 0) << "rounds with a thread outside the published group";
	EXPECT_EQ(wrong_count, 0) << "rounds in which the group does not count " << N << " threads";
	EXPECT_EQ(wrong_list, 0) << "rounds in which the group does not list " << N << " threads";
}

// Control of D5: the same threads added one after the other.
TEST_F(thread_manager_defects, sequential_adds_of_one_new_process_make_one_group) {
	add_default_init_thread();
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	for(int round = 0; round < 50; round++) {
		const int64_t pid = 30000 + round * 16;
		for(int i = 0; i < 8; i++) {
			manager->add_thread(make_thread(pid + i, pid), true);
		}
		auto group = manager->get_thread_group_info(pid);
		ASSERT_NE(group, nullptr);
		ASSERT_EQ(group->get_thread_count(), 8u);
		ASSERT_EQ(group->get_thread_list().size(), 8u);
		for(int i = 0; i < 8; i++) {
			ASSERT_EQ(manager->find_thread(pid + i, true)->get_tginfo(), group);
		}
	}
}

// Control of D9: the same thread removed twice, one after the other.
TEST_F(thread_manager_defects, sequential_removals_decrement_the_group_once) {
	add_default_init_thread();
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	for(int i = 0; i < 3; i++) {
		manager->add_thread(make_thread(60000 + i, 60000), true);
	}
	manager->remove_thread(60001);
	manager->remove_thread(60001);
	EXPECT_EQ(manager->get_thread_group_info(60000)->get_thread_count(), 2u);
}

// D9 (REVIEW-2853 sec. 6): "if(!is_dead()) { decrement_thread_count(); set_dead(); }" is not atomic
// (sinsp_thread_manager::remove_thread, and parse_thread_exit). When the exit parser and the purge,
// or two removals, reach the same thread together, the group is decremented twice.
TEST_F(thread_manager_defects, DISABLED_D9_concurrent_removals_decrement_the_group_once) {
	add_default_init_thread();
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	constexpr int ROUNDS = 3000;
	int bad_rounds = 0;
	for(int round = 0; round < ROUNDS; round++) {
		const int64_t pid = 60000 + round * 4;
		for(int i = 0; i < 3; i++) {
			manager->add_thread(make_thread(pid + i, pid), true);
		}
		run_together(2, [&](int) { manager->remove_thread(pid + 1); });
		auto group = manager->get_thread_group_info(pid);
		if(group == nullptr || group->get_thread_count() != 2) {
			bad_rounds++;
		}
	}
	EXPECT_EQ(bad_rounds, 0) << "rounds in which the alive count of the group is wrong";
}
#endif

// D14 (REVIEW-2853 sec. 6): thread_group_info::for_each_thread() runs the callback under the
// shared lock (thread_group_info.h). A callback that modifies the group (add_thread_to_group takes
// the exclusive lock) deadlocks. The body runs in a child process with an alarm, so that the
// deadlock is a failure and not a hang.
TEST_F(thread_manager_defects, DISABLED_D14_for_each_thread_callback_can_modify_the_group) {
	add_default_init_thread();
	open_inspector();
	auto* manager = m_inspector.m_thread_manager.get();
	manager->add_thread(make_thread(500, 500), true);
	auto group = manager->get_thread_group_info(500);
	ASSERT_NE(group, nullptr);
	auto extra = manager->find_thread(500, true);
	ASSERT_NE(extra, nullptr);
	EXPECT_EXIT(
	        {
		        alarm(5);
		        group->for_each_thread([&](const std::shared_ptr<sinsp_threadinfo>& t) {
			        group->add_thread_to_group(t, false);
			        return false;
		        });
		        std::_Exit(0);
	        },
	        ::testing::ExitedWithCode(0),
	        "")
	        << "the callback of for_each_thread() deadlocked on the group lock";
}

namespace {
struct dyn_struct : public libsinsp::state::extensible_struct {
	explicit dyn_struct(const std::shared_ptr<libsinsp::state::dynamic_field_infos>& i):
	        extensible_struct(i) {}
};
}  // namespace

// The writes of D11, from `n_threads` threads (1: one after the other). Returns the number of
// fields that do not hold the value that was written.
static int write_dynamic_fields(int n_threads) {
	constexpr int N_FIELDS = 8;
	constexpr int ROUNDS = 2000;
	auto defs = libsinsp::state::dynamic_field_infos::make<dyn_struct>();
	using acc_t = decltype(defs->add_field("x", SS_PLUGIN_ST_UINT64).into<uint64_t>());
	std::vector<acc_t> accs;
	for(int i = 0; i < N_FIELDS; i++) {
		accs.push_back(
		        defs->add_field("f" + std::to_string(i), SS_PLUGIN_ST_UINT64).into<uint64_t>());
	}
	int bad = 0;
	for(int r = 0; r < ROUNDS; r++) {
		dyn_struct s(defs);
		if(n_threads == 1) {
			for(int i = 0; i < N_FIELDS; i++) {
				s.write_field(accs[i], static_cast<uint64_t>(i + 1));
			}
		} else {
			run_together(N_FIELDS,
			             [&](int i) { s.write_field(accs[i], static_cast<uint64_t>(i + 1)); });
		}
		for(int i = 0; i < N_FIELDS; i++) {
			uint64_t v = 0;
			s.read_field(accs[i], v);
			bad += v != static_cast<uint64_t>(i + 1);
		}
	}
	return bad;
}

// Control of D11: the same writes, one after the other.
TEST(multi_thread_defects, sequential_first_writes_of_different_dynamic_fields) {
	EXPECT_EQ(write_dynamic_fields(1), 0);
}

// D11 (REVIEW-2853 sec. 6): the dynamic fields of an entry live in a vector that is grown on the
// first write of a field, without any lock (state/extensible_struct.h,
// _access_dynamic_field_for_write: m_fields.emplace_back). Two threads writing different dynamic
// fields of the same threadinfo or fdinfo race on the vector. The body runs in a child process
// because the race can crash.
TEST(multi_thread_defects, DISABLED_D11_concurrent_first_writes_of_different_dynamic_fields) {
	EXPECT_EXIT(
	        { std::_Exit(write_dynamic_fields(8) == 0 ? 0 : 3); },
	        ::testing::ExitedWithCode(0),
	        "")
	        << "a write of a dynamic field was lost, or the vector of the fields was corrupted";
}
