// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#include <map>
#include <tuple>
#include <type_traits>
#include <libsinsp/state/table.h>
#include <libsinsp/fdinfo.h>
#include <libsinsp/plugin.h>
#include <libsinsp/sinsp_fdinfo_factory.h>
#include <libsinsp/sinsp_mode.h>

#ifdef LIBSINSP_USE_FOLLY
#include <folly/concurrency/ConcurrentHashMap.h>
#endif

// Forward declare sinsp_stats_v2 to avoid including metrics_collector.h here.
class sinsp_stats_v2;

struct sinsp_fdtable_ctor_params {
	// The following fields are externally provided and access to them is expected to be
	// read-only.
	const sinsp_mode& m_sinsp_mode;
	const uint32_t m_max_table_size;
	const sinsp_fdinfo_factory m_fdinfo_factory;
	const std::shared_ptr<const sinsp_plugin> m_input_plugin;

	// The following fields are externally provided and expected to be populated/updated by the
	// fdtable.
	std::shared_ptr<sinsp_stats_v2> m_sinsp_stats_v2;
	scap_platform* const& m_scap_platform;
};

///////////////////////////////////////////////////////////////////////////////
// fd info table
//
// Two storage strategies, picked by the sync policy:
//  - single-threaded policy: the table contents live behind a shared_ptr, so that the fd tables
//    of related processes share them at fork and copy them on write (share_from(), find_mut());
//  - concurrent policy: the contents are a concurrent map (or a mutex-protected one) that is
//    never shared between tables: share_from() copies the entries instead, because the tables of
//    a parent and a child may be used by different workers at the same time.
///////////////////////////////////////////////////////////////////////////////
template<typename SyncPolicy = sync_policy_default>
class sinsp_fdtable_impl : public libsinsp::state::extensible_table<int64_t> {
public:
	using traits = libsinsp::sync_policy_traits<SyncPolicy>;
	using fdinfo_t = sinsp_fdinfo_impl<SyncPolicy>;
	using ctor_params = sinsp_fdtable_ctor_params;
	typedef std::function<bool(int64_t, fdinfo_t&)> fdtable_visitor_t;
	typedef std::function<bool(int64_t, const fdinfo_t&)> fdtable_const_visitor_t;

	// True if the table contents are shared between tables and copied on write.
	static constexpr bool k_cow = std::is_same_v<SyncPolicy, sync_policy_single>;

	explicit sinsp_fdtable_impl(const std::shared_ptr<ctor_params>& params);

	// Read-only lookup: the returned entry must not be modified, as it may be
	// shared with other fd tables.
	std::shared_ptr<const fdinfo_t> find(int64_t fd) const;

	// Lookup for modification: the single chokepoint through which every
	// mutable entry is handed out.
	std::shared_ptr<fdinfo_t> find_mut(int64_t fd);

	std::shared_ptr<fdinfo_t> add(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo);

	// Shares table contents with `other` (typically the parent process's
	// table at fork). Both tables then see the same entries; the first
	// content modification through either table detaches a private copy
	// (copy-on-write), leaving the other sharers untouched.
	// With the concurrent policy the entries are copied right away instead.
	void share_from(const sinsp_fdtable_impl& other);

	// True if the contents are currently shared with at least one other fd
	// table. Always false with the concurrent policy.
	bool is_shared() const {
		if constexpr(k_cow) {
			return m_table.use_count() > 1;
		} else {
			return false;
		}
	}

	// Identity of the current contents: tables sharing contents report the
	// same value, letting accountants count shared contents once.
	const void* contents_id() const {
		if constexpr(k_cow) {
			return m_table.get();
		} else {
			return &m_table;
		}
	}

	inline bool const_loop(const fdtable_const_visitor_t callback) const {
		if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
			for(auto it = m_table.cbegin(); it != m_table.cend(); ++it) {
				std::shared_ptr<fdinfo_t> pin = it->second;
				if(!pin) {
					continue;
				}
				if(!callback(it->first, *pin)) {
					return false;
				}
			}
#endif
		} else {
			std::shared_lock lock(m_mutex);
			const auto& map = tbl();
			for(auto it = map.begin(); it != map.end(); ++it) {
				if(!callback(it->first, *it->second)) {
					return false;
				}
			}
		}
		return true;
	}

	inline bool loop(const fdtable_visitor_t callback) {
		if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
			for(auto it = m_table.begin(); it != m_table.end(); ++it) {
				std::shared_ptr<fdinfo_t> pin = it->second;
				if(!pin) {
					continue;
				}
				if(!callback(it->first, *pin)) {
					return false;
				}
			}
#endif
		} else {
			std::shared_lock lock(m_mutex);
			auto& map = tbl();
			if(map.empty()) {
				// Nothing to visit; in particular, don't detach shared contents
				// (proc-scan fixups run on freshly created, still-empty tables).
				return true;
			}
			detach_if_shared();
			for(auto it = map.begin(); it != map.end(); ++it) {
				if(!callback(it->first, *slot_mut(it))) {
					return false;
				}
			}
		}
		return true;
	}

	void retain(const fdtable_const_visitor_t& callback);

	// Registry used to deduplicate content-identical entries across the fd
	// tables built by the initial /proc scan (fork-inherited fds appear once
	// per process there). Same fd number, device and inode across processes
	// is the fork-inheritance signature; full content equality decides.
	struct dedup_registry {
		using key_t = std::tuple<int64_t, uint32_t, uint64_t>;  // fd, dev, ino
		std::map<key_t, std::vector<std::pair<std::shared_ptr<fdinfo_t>, sinsp_fdtable_impl*>>>
		        m_candidates;
	};

	// Replaces entries for which the registry already holds a
	// content-identical canonical entry, and registers the rest as canonical
	// candidates. Only meaningful right after the initial scan, before any
	// event touches the tables; copy-on-write covers later divergence.
	// A no-op with the concurrent policy, whose tables never share entries.
	void deduplicate_into(dedup_registry& registry);

	// If the key is present, returns true, otherwise returns false.
	bool erase(int64_t fd);

	void clear();

	size_t size() const;

	void reset_cache() const;

	inline uint64_t get_tid() const { return m_tid; }

	inline void set_tid(uint64_t v) { m_tid = v; }

	// ---- libsinsp::state::table implementation ----

	size_t entries_count() const override { return size(); }

	void clear_entries() override { clear(); }

	std::unique_ptr<libsinsp::state::table_entry> new_entry() const override;

	bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
		return loop([&pred](int64_t i, fdinfo_t& e) { return pred(e); });
	}

	std::shared_ptr<libsinsp::state::table_entry> get_entry(const int64_t& key) override;

	std::shared_ptr<libsinsp::state::table_entry> add_entry(
	        const int64_t& key,
	        std::unique_ptr<libsinsp::state::table_entry> entry) override {
		if(!entry) {
			throw sinsp_exception("null entry added to fd table");
		}
		auto fdinfo = dynamic_cast<fdinfo_t*>(entry.get());
		if(!fdinfo) {
			throw sinsp_exception("unknown entry type added to fd table");
		}
		entry.release();

		return add(key, std::shared_ptr<fdinfo_t>(fdinfo));
	}

	bool erase_entry(const int64_t& key) override { return erase(key); }

	// Lock order: when both fdtable (m_mutex) and fdinfo (sinsp_fdinfo::m_mutex) are needed,
	// always take fdtable first, then fdinfo. Violating this can cause lock-order inversion
	// and deadlock (see set_net_role_by_guessing in fdinfo.cpp).
	mutable typename traits::fdtable_outer_mutex m_mutex;

private:
	// Parameters provided at fdtable construction phase.
	// Notice: the struct instance is shared among all fdtable instances.
	// Notice 2: this should be a plain const reference, but use a shared_ptr or the compiler will
	// complain about referencing a member (m_input_plugin) whose lifetime is shorter than the
	// ctor_params object in sinsp constructor.
	const std::shared_ptr<ctor_params> m_params;

#ifdef LIBSINSP_USE_FOLLY
	using folly_map_t = folly::ConcurrentHashMap<int64_t, std::shared_ptr<fdinfo_t>>;
#endif
	using std_map_t = std::unordered_map<int64_t, std::shared_ptr<fdinfo_t>>;

	using map_type = std::conditional_t<traits::k_use_folly_chm,
#ifdef LIBSINSP_USE_FOLLY
	                                    folly_map_t,
#else
	                                    std_map_t,
#endif
	                                    std_map_t>;

	// The table contents. With the single-threaded policy they are held through a shared_ptr so
	// that the fd tables of related processes can share them; a shared map is never modified in
	// place (see detach_if_shared()).
	using contents_t = std::conditional_t<k_cow, std::shared_ptr<std_map_t>, map_type>;
	contents_t m_table;

	inline auto& tbl() {
		if constexpr(k_cow) {
			return *m_table;
		} else {
			return m_table;
		}
	}

	inline const auto& tbl() const {
		if constexpr(k_cow) {
			return *m_table;
		} else {
			return m_table;
		}
	}

	// True if this table's entries may be referenced by other fd tables,
	// i.e. share_from() has ever put these contents in play. While false,
	// entry reference counts have only private causes (caches, plugin
	// entry handles) and writable access never copies. Sticky per contents
	// generation; sharing metadata like the cache, hence mutable.
	mutable bool m_entries_maybe_shared{false};

#ifdef LIBSINSP_USE_FOLLY
	struct fd_cache_entry {
		const sinsp_fdtable_impl* table{nullptr};
		int64_t fd{-1};
		std::shared_ptr<fdinfo_t> fdinfo;
	};

	static fd_cache_entry& tl_cache() {
		static thread_local fd_cache_entry entry;
		return entry;
	}

	inline void invalidate_tl_cache() const {
		auto& c = tl_cache();
		if(c.table == this) {
			c.fd = -1;
			c.fdinfo.reset();
		}
	}
#endif

	// Simple fd cache, used with the single-threaded policy only. This is
	// per-owner memoization, not table content: it stays mutable so that
	// read-only lookups on a const table can still maintain it.
	mutable int64_t m_last_accessed_fd{-1};
	mutable std::shared_ptr<fdinfo_t> m_last_accessed_fdinfo;
	uint64_t m_tid;

	bool is_syscall_plugin_enabled() const {
		return m_params && m_params->m_sinsp_mode.is_plugin() && m_params->m_input_plugin &&
		       m_params->m_input_plugin->id() == 0;
	}

	// The shared immutable empty contents that every fd table starts out
	// referencing (single-threaded policy): threads that never own fds (all
	// non-main threads) pay no allocation. The first modification detaches a
	// private map like any other write to shared contents.
	static const std::shared_ptr<std_map_t>& empty_contents();

	// Gives this table private contents before an in-place modification.
	// Returns true if a detach actually took place (invalidating iterators
	// and entry pointers previously obtained from this table).
	bool detach_if_shared();

	// Gives the slot a private entry before mutable access is handed out.
	// The caller must already own private contents (detach_if_shared()).
	template<typename It>
	inline fdinfo_t* slot_mut(const It& it) {
		auto& slot = it->second;
		if constexpr(!k_cow) {
			return slot.get();
		} else {
			// Entries can only be referenced by other tables after share_from()
			// has been involved; without that, extra references (plugin entry
			// handles, caches) are private to this table and must keep observing
			// in-place writes, so no copy may be made.
			if(!m_entries_maybe_shared || slot.use_count() <= 1) {
				return slot.get();
			}
			// Disarm our own cache reference first: it would both inflate the
			// reference count below and keep serving the pre-copy entry
			// afterwards. This cannot free the entry: the slot still owns it.
			if(m_last_accessed_fdinfo == slot) {
				m_last_accessed_fd = -1;
				m_last_accessed_fdinfo.reset();
			}
			// Any remaining reference may be another table's slot or cache:
			// copy before writing. Spurious copies (a stale cache elsewhere, a
			// plugin entry handle on a once-shared table, an event holding the entry)
			// are safe, just wasteful.
			if(slot.use_count() > 1) {
				slot = std::shared_ptr<fdinfo_t>(slot->clone());
			}
			return slot.get();
		}
	}

	inline void lookup_device(fdinfo_t& fdi) const;
	std::shared_ptr<fdinfo_t> find_ref(int64_t fd) const;
	std::shared_ptr<fdinfo_t> add_ref(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo);
};

using sinsp_fdtable = sinsp_fdtable_impl<>;
