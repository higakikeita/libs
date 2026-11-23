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

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include <sys/wait.h>

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
