// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdint.h>
#include <list>

#include <libsinsp/sinsp_exception.h>
#include <libsinsp/sinsp_public.h>
#include <libsinsp/sync_policy.h>

template<typename SyncPolicy>
class sinsp_threadinfo_impl;
using sinsp_threadinfo = sinsp_threadinfo_impl<sync_policy_default>;

/* Apart from the main thread all other threads when marked as dead should be removed
 * from the thread_table at the next event loop and so become expired. For this reason when we have
 * at least `n` dead threads we can try to clean up expired ones.
 */
#define DEFAULT_DEAD_THREADS_THRESHOLD 11

/* New struct that keep information regarding the thread group.
 * All access to m_threads, m_alive_count, m_reaper and the parent link (m_parent, m_parent_tid,
 * m_dead, m_link_refused) is protected by m_mutex for thread safety. The rank is atomic, so that a
 * group can read the rank of another one without nesting locks: the parent links go down in rank,
 * thus locks taken child-then-parent can never form a cycle.
 */
struct thread_group_info {
public:
	/* An entry of the thread list of the group. The thread table owns the threads. In the
	 * multi-thread build another worker may erase a thread at any time, so readers always take a
	 * reference with lock().
	 */
	class thread_ref {
	public:
		thread_ref(const std::shared_ptr<sinsp_threadinfo>& thread): m_weak(thread) {}
		thread_ref(const std::weak_ptr<sinsp_threadinfo>& thread): m_weak(thread) {}

		inline bool expired() const { return m_weak.expired(); }
		inline std::shared_ptr<sinsp_threadinfo> lock() const { return m_weak.lock(); }

	private:
		std::weak_ptr<sinsp_threadinfo> m_weak;
	};

	thread_group_info(int64_t group_pid,
	                  bool reaper,
	                  std::weak_ptr<sinsp_threadinfo> current_thread):
	        m_pid(group_pid),
	        m_reaper(reaper) {
		if(current_thread.expired()) {
			throw sinsp_exception("we cannot create a thread group info from an expired thread");
		}

		/* When we create the thread group info the count is 1, because we only have the creator
		 * thread */
		std::unique_lock lock(m_mutex);
		m_alive_count = 1;
		m_threads.push_front(current_thread);
	}

	inline void increment_thread_count() {
		std::unique_lock lock(m_mutex);
		m_alive_count++;
	}

	inline void decrement_thread_count() {
		std::unique_lock lock(m_mutex);
		m_alive_count--;

		/* Clean expired threads if necessary.
		 * Please note that this is an approximation, `m_threads.size() - m_alive_count` are not the
		 * real expired threads, they are just the ones marked as dead. For example the main thread
		 * of the group is marked as dead but it will be never expired until the thread group
		 * exists.
		 */
		if((m_threads.size() - m_alive_count) >= DEFAULT_DEAD_THREADS_THRESHOLD) {
			clean_expired_threads(lock);
		}
	}

	inline uint64_t get_thread_count() const {
		std::shared_lock lock(m_mutex);
		return m_alive_count;
	}

	inline bool is_reaper() const {
		std::shared_lock lock(m_mutex);
		return m_reaper;
	}

	inline void set_reaper(bool reaper) {
		std::unique_lock lock(m_mutex);
		m_reaper = reaper;
	}

	inline int64_t get_tgroup_pid() const { return m_pid; }

	/** Returns a copy of the thread list so the result is safe to use after the lock is released.
	 */
	inline std::list<thread_ref> get_thread_list() const {
		std::shared_lock lock(m_mutex);
		return m_threads;
	}

	/** Iterate over non-expired threads under a shared lock, without copying the list.
	 *  The callback receives a shared_ptr to each live thread. Return true to continue
	 *  iteration, false to stop early. Returns true if all elements were visited.
	 */
	template<typename F>
	inline bool for_each_thread(F&& fn) const {
		std::shared_lock lock(m_mutex);
		for(const auto& wp : m_threads) {
			if(auto sp = wp.lock()) {
				if(!fn(sp)) {
					return false;
				}
			}
		}
		return true;
	}

	/** Find the first thread matching a predicate, without copying the list.
	 *  The predicate receives a const shared_ptr<sinsp_threadinfo>&.
	 *  Returns the matching thread or nullptr if none matches.
	 */
	template<typename Pred>
	inline std::shared_ptr<sinsp_threadinfo> find_thread(Pred&& pred) const {
		std::shared_lock lock(m_mutex);
		for(const auto& wp : m_threads) {
			if(auto sp = wp.lock()) {
				if(pred(sp)) {
					return sp;
				}
			}
		}
		return nullptr;
	}

	inline void add_thread_to_group(const std::shared_ptr<sinsp_threadinfo>& thread, bool main) {
		std::unique_lock lock(m_mutex);
		/* The main thread should always be the first element of the list, if present.
		 * In this way we can efficiently obtain the main thread.
		 */
		if(main) {
			m_threads.push_front(thread);
		} else {
			m_threads.push_back(thread);
		}
		m_alive_count++;
	}

	inline void clean_expired_threads() {
		std::unique_lock lock(m_mutex);
		clean_expired_threads(lock);
	}

	/* Remove a specific thread from the list immediately (e.g. when using
	 * concurrent map with deferred reclamation, so weak_ptrs may not expire
	 * in time for clean_expired_threads to remove them).
	 */
	inline void remove_thread_from_list(const std::shared_ptr<sinsp_threadinfo>& thread) {
		std::unique_lock lock(m_mutex);
		for(auto it = m_threads.begin(); it != m_threads.end(); ++it) {
			auto locked = it->lock();
			if(locked.get() == thread.get()) {
				m_threads.erase(it);
				return;
			}
		}
	}

	/* A tombstone has no threads, so the list can be empty. */
	inline std::shared_ptr<sinsp_threadinfo> get_first_thread() const {
		std::shared_lock lock(m_mutex);
		if(m_threads.empty()) {
			return nullptr;
		}
		return m_threads.front().lock();
	}

	/* The parent process is the group of the thread that forked, and the tid of that thread.
	 * Only the child side of the link is stored. The parent keeps no list of children.
	 *
	 * The writer resolves the link when it writes it, and readers only follow it. A null link
	 * with a tid is a parent that we do not know (yet).
	 *
	 * Every link goes down in rank, so the links never form a cycle. The rank of a group is set
	 * before anything can link to the group, and it never changes. The rank is the rank of the
	 * parent plus one, 0 without a parent, and s_unknown_parent_rank when the parent is unknown.
	 * The high rank lets sinsp link the group to its parent later. A link to a group of the same
	 * rank or higher is refused. Thus, the test of a link needs only the two groups.
	 */
	static constexpr uint64_t s_unknown_parent_rank = uint64_t{1} << 62;

	/* Link a group that nothing links to yet, and set its rank. If the rank of the parent is
	 * pending (also when the parent is this group), the link is refused. Then the function keeps
	 * the tid and returns false.
	 */
	inline bool link_new(std::shared_ptr<thread_group_info> parent, int64_t parent_tid) {
		std::unique_lock lock(m_mutex);
		if(parent != nullptr && parent->get_rank() != s_pending_rank) {
			m_rank.store(parent->get_rank() + 1);
			m_parent = std::move(parent);
			m_parent_tid = parent_tid;
			return true;
		}
		m_rank.store(parent_tid > 0 ? s_unknown_parent_rank : 0);
		m_parent = nullptr;
		m_parent_tid = parent_tid;
		return parent == nullptr;
	}

	/* Use this for a group that is published before it is linked, because the /proc scan creates
	 * its parent first. Nothing can link to the group until link_new() sets its rank.
	 */
	inline void set_rank_pending() { m_rank.store(s_pending_rank); }

	/* Link to `parent` unless that link goes up in rank. A refused link stores nothing. */
	inline bool relink(std::shared_ptr<thread_group_info> parent, int64_t parent_tid) {
		std::unique_lock lock(m_mutex);
		if(parent->get_rank() >= m_rank.load()) {
			return false;
		}
		m_parent = std::move(parent);
		m_parent_tid = parent_tid;
		m_link_refused = false;
		return true;
	}

	/* Drop the link to the group of the parent, but keep the parent tid. */
	inline void unlink(int64_t parent_tid) {
		std::unique_lock lock(m_mutex);
		m_parent = nullptr;
		m_parent_tid = parent_tid;
		m_link_refused = false;
	}

	/* The link to `m_parent_tid` was refused, so sinsp does not try it again. */
	inline void set_link_refused() {
		std::unique_lock lock(m_mutex);
		m_link_refused = true;
	}

	/* True if a link to the parent known only by its tid is still to be tried. */
	inline bool awaits_parent() const {
		std::shared_lock lock(m_mutex);
		return m_parent == nullptr && m_parent_tid > 0 && !m_link_refused && !m_dead;
	}

	inline uint64_t get_rank() const { return m_rank.load(); }

	/* The parent group is returned by value: another worker may relink the group at any time. */
	inline std::shared_ptr<thread_group_info> get_parent() const {
		std::shared_lock lock(m_mutex);
		return m_parent;
	}

	inline int64_t get_parent_tid() const {
		std::shared_lock lock(m_mutex);
		return m_parent_tid;
	}

	/* True if the chain of parent links ends (has no cycle). For asserts and tests only. */
	inline bool chain_ends() const {
		uint64_t steps = 0;
		for(auto cur = get_parent(); cur != nullptr; cur = cur->get_parent()) {
			if(++steps > (uint64_t{1} << 24)) {
				return false;
			}
		}
		return true;
	}

	/* A dead group is a tombstone (a group that stays after its process is gone). It leaves the
	 * group table with its last thread, and it lives while a child links to it. sinsp picks the
	 * reaper when the group dies, and the reaper replaces the parent link. If sinsp finds no
	 * reaper, the link is empty, and the children of the tombstone have no parent. The link of a
	 * tombstone never changes.
	 */
	inline void set_dead() {
		std::unique_lock lock(m_mutex);
		m_dead = true;
		m_threads.clear();
	}

	/* For a dying group: link to its reaper, unless that link goes up in rank. */
	inline bool link_reaper(std::shared_ptr<thread_group_info> reaper, int64_t reaper_tid) {
		std::unique_lock lock(m_mutex);
		if(reaper->get_rank() >= m_rank.load()) {
			return false;
		}
		m_parent = std::move(reaper);
		m_parent_tid = reaper_tid;
		return true;
	}

	inline bool is_dead() const {
		std::shared_lock lock(m_mutex);
		return m_dead;
	}

	/* Link straight to `parent`, where the dead parent `seen` leads. The tombstones in between
	 * are freed when nothing links to them. If the link is no longer `seen`, nothing is stored,
	 * so a relink in between wins.
	 */
	inline void skip_dead_parent(const thread_group_info* seen,
	                             std::shared_ptr<thread_group_info> parent,
	                             int64_t parent_tid) {
		ASSERT(parent->get_rank() < m_rank.load());
		before_shortcut_store();
		std::unique_lock lock(m_mutex);
		if(m_parent.get() != seen) {
			return;
		}
		m_parent = std::move(parent);
		m_parent_tid = parent_tid;
	}

#ifdef _DEBUG
	/* Tests only: called between the walk and the store of a shortcut. */
	static inline std::function<void()> s_before_shortcut_store;
#endif

private:
	/** Called with m_mutex already held (unique_lock). */
	inline void clean_expired_threads(std::unique_lock<std::shared_mutex>&) {
		auto thread = m_threads.begin();
		while(thread != m_threads.end()) {
			if(thread->expired()) {
				thread = m_threads.erase(thread);
				continue;
			}
			thread++;
		}
	}

	inline void before_shortcut_store() const {
#ifdef _DEBUG
		if(s_before_shortcut_store) {
			s_before_shortcut_store();
		}
#endif
	}

	static constexpr uint64_t s_pending_rank = UINT64_MAX;

	int64_t m_pid; /* unsigned if we want to use `-1` as an invalid value */
	mutable std::shared_mutex m_mutex;
	uint64_t m_alive_count;
	std::list<thread_ref> m_threads;
	std::shared_ptr<thread_group_info> m_parent;
	int64_t m_parent_tid = 0;
	std::atomic<uint64_t> m_rank{s_unknown_parent_rank};
	bool m_reaper;
	bool m_dead = false;
	bool m_link_refused = false;
};
