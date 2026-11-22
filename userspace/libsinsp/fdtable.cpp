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

#ifndef _WIN32
#include <algorithm>
#endif
#include <cinttypes>

#include <libsinsp/fdtable.h>
#include <libsinsp/sinsp_int.h>
#include <libscap/scap-int.h>

static const auto s_fdtable_static_fields = sinsp_fdinfo::get_static_fields();

template<typename SyncPolicy>
const std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::std_map_t>&
sinsp_fdtable_impl<SyncPolicy>::empty_contents() {
	static const std::shared_ptr<std_map_t> s_empty = std::make_shared<std_map_t>();
	return s_empty;
}

template<typename SyncPolicy>
sinsp_fdtable_impl<SyncPolicy>::sinsp_fdtable_impl(const std::shared_ptr<ctor_params>& params):
        extensible_table{type_tag<sinsp_fdinfo_impl<SyncPolicy>>{},
                         "file_descriptors",
                         &s_fdtable_static_fields},
        m_params{params},
        m_tid{0} {
	if constexpr(k_cow) {
		m_table = empty_contents();
	}
	reset_cache();
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::find_ref(int64_t fd) const {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		auto& c = tl_cache();
		if(c.table_id == m_cache_id && c.fd == fd) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_cached_fd_lookups();
			}
			return c.fdinfo;
		}

		auto fdit = m_table.find(fd);
		if(fdit == m_table.end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}

		// Lazily resolve the device number of file entries coming from a proc scan.
		lookup_device(*fdit->second);

		c.table_id = m_cache_id;
		c.fd = fd;
		c.fdinfo = fdit->second;
		return c.fdinfo;
#endif
	} else if constexpr(k_cow) {
		//
		// Try looking up in our simple cache
		//
		if(m_last_accessed_fd != -1 && fd == m_last_accessed_fd) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_cached_fd_lookups();
			}
			return m_last_accessed_fdinfo;
		}

		//
		// Caching failed, do a real lookup
		//
		auto fdit = m_table->find(fd);

		if(fdit == m_table->end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}

		m_last_accessed_fd = fd;
		m_last_accessed_fdinfo = fdit->second;
		lookup_device(*m_last_accessed_fdinfo);
		return m_last_accessed_fdinfo;
	} else {
		std::shared_lock lock(m_mutex);

		auto fdit = m_table.find(fd);
		if(fdit == m_table.end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}

		lookup_device(*fdit->second);
		return fdit->second;
	}
	return nullptr;
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::share_from(const sinsp_fdtable_impl& other) {
	if constexpr(k_cow) {
		m_table = other.m_table;
		// From now on both tables' entries may be referenced across tables, so
		// writable access must copy entries (see slot_mut()). An empty map
		// has no entries to share, which keeps the flag off for tables still
		// referencing the shared empty contents.
		m_entries_maybe_shared = !m_table->empty();
		other.m_entries_maybe_shared = m_entries_maybe_shared;
		reset_cache();
	} else {
		// The tables of a parent and of its child may be used by different workers
		// concurrently: copy the entries instead of sharing them.
		clear();
		other.const_loop([this](int64_t fd, const fdinfo_t& fdi) {
			auto copy = std::shared_ptr<fdinfo_t>(fdi.clone());
			add_ref(fd, std::move(copy));
			return true;
		});
	}
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::deduplicate_into(dedup_registry& registry) {
	if constexpr(k_cow) {
		if(m_table->empty() || is_shared()) {
			// Wholesale-shared contents are already deduplicated; without private
			// contents we must not rebind slots in place.
			return;
		}

		for(auto& [fd, info] : *m_table) {
			if(info->has_dynamic_field_values()) {
				// Dynamic field values are not covered by content_equals().
				continue;
			}
			auto& bucket = registry.m_candidates[{fd, info->get_dev(), info->get_ino()}];
			bool deduplicated = false;
			for(const auto& [canonical, owner] : bucket) {
				if(canonical->content_equals(*info)) {
					info = canonical;
					m_entries_maybe_shared = true;
					owner->m_entries_maybe_shared = true;
					deduplicated = true;
					break;
				}
			}
			if(!deduplicated) {
				bucket.emplace_back(info, this);
			}
		}
		reset_cache();
	}
}

template<typename SyncPolicy>
bool sinsp_fdtable_impl<SyncPolicy>::detach_if_shared() {
	if constexpr(k_cow) {
		if(!is_shared()) {
			return false;
		}

		// Shallow detach: this table gets a private map referencing the same
		// entries. Entries are copied individually when handed out for
		// modification (see slot_mut()), so inherited fds that are never
		// modified stay shared for their whole life.
		m_table = std::make_shared<std_map_t>(*m_table);
		m_entries_maybe_shared = !m_table->empty();

		// The cache key refers to the previously shared contents.
		reset_cache();
		return true;
	} else {
		return false;
	}
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::retain(const fdtable_const_visitor_t& callback) {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		// Invalidate the thread-local fd cache, otherwise a later lookup could return an entry
		// removed here (the same hazard erase() guards against).
		invalidate_tl_cache();
		for(auto it = m_table.begin(); it != m_table.end();) {
			if(!callback(it->first, *it->second)) {
				it = m_table.erase(it);
			} else {
				++it;
			}
		}
#endif
	} else {
		std::unique_lock lock(m_mutex);
		auto& map = tbl();
		if(map.empty()) {
			return;
		}
		if constexpr(k_cow) {
			if(is_shared()) {
				// Build the private map directly from the surviving slots: the
				// fork->execve path retains only the non-CLOEXEC subset. The
				// entries themselves stay shared; copy-on-write covers later
				// modifications.
				auto retained = std::make_shared<std_map_t>();
				for(const auto& [fd, info] : *m_table) {
					if(callback(fd, *info)) {
						retained->emplace(fd, info);
					}
				}
				m_table = std::move(retained);
				m_entries_maybe_shared = !m_table->empty();
				reset_cache();
				return;
			}
		}
		for(auto it = map.begin(); it != map.end();) {
			if(!callback(it->first, *it->second)) {
				// Invalidate the cache if we are removing the cached fd, otherwise a
				// later lookup would return a dangling entry (the same hazard erase()
				// guards against).
				if(it->first == m_last_accessed_fd) {
					reset_cache();
				}
				it = map.erase(it);
			} else {
				++it;
			}
		}
	}
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::add_ref(int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo) {
	std::unique_lock lock(m_mutex);

	if(fdinfo->dynamic_fields() != dynamic_fields()) {
		throw sinsp_exception("adding entry with incompatible dynamic defs to fd table");
	}

	fdinfo->set_fd_num(fd);

	const uint32_t max_size = m_params ? m_params->m_max_table_size : 0xFFFFFFFFU;

	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		if(m_table.size() >= max_size) {
			auto it = m_table.find(fd);
			if(it == m_table.end()) {
				return nullptr;
			}
		}

		invalidate_tl_cache();

		auto [it, inserted] = m_table.insert_or_assign(fd, std::move(fdinfo));
		if(inserted && m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_added_fds();
		}
		return it->second;
#endif
	} else {
		auto& map = tbl();
		auto it = map.find(fd);

		// Three possible exits here:
		// 1. fd is not on the table
		//   a. the table size is under the limit so create a new entry
		//   b. table size is over the limit, discard the fd
		// 2. fd is already in the table, replace it
		if(it == map.end()) {
			if(map.size() == max_size) {
				return nullptr;
			}
			detach_if_shared();

			// No entry in the table, this is the normal case.
			m_last_accessed_fd = -1;
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_added_fds();
			}

			auto& ref = tbl().emplace(fd, std::move(fdinfo)).first->second;
			return ref;
		}

		// The fd is already in the table. This can happen if:
		//  - the event is a dup2 or dup3 that overwrites an existing FD (perfectly legal)
		//  - a close() has been dropped when capturing
		//  - an fd has been closed by clone() or execve() (it happens when the fd is opened
		//  with the FD_CLOEXEC flag, which we don't currently parse.
		// In either case, removing the old fd, replacing it with the new one and keeping going
		// is a reasonable choice.

		// Replace the fd as a struct copy.
		if(detach_if_shared()) {
			it = tbl().find(fd);
		}
		m_last_accessed_fd = -1;
		it->second = std::move(fdinfo);
		return it->second;
	}
	return nullptr;
}

template<typename SyncPolicy>
bool sinsp_fdtable_impl<SyncPolicy>::erase(int64_t fd) {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();

		auto erased = m_table.erase(fd);
		if(erased == 0) {
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return false;
		}
		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			auto& c = m_params->m_sinsp_stats_v2->get_thread_counters();
			c.inc_n_noncached_fd_lookups();
			c.inc_n_removed_fds();
		}
		return true;
#endif
	} else {
		std::unique_lock lock(m_mutex);
		auto& map = tbl();
		auto fdit = map.find(fd);

		if(fd == m_last_accessed_fd) {
			reset_cache();
		}

		if(fdit == map.end()) {
			//
			// Looks like there's no fd to remove.
			// Either the fd creation event was dropped or (more likely) our logic doesn't support
			// the call that created this fd. In release mode we just keep going.
			//
			if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return false;
		}

		if(detach_if_shared()) {
			fdit = tbl().find(fd);
		}
		tbl().erase(fdit);
		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			auto& c = m_params->m_sinsp_stats_v2->get_thread_counters();
			c.inc_n_noncached_fd_lookups();
			c.inc_n_removed_fds();
		}
		return true;
	}
	return false;
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::clear() {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();
		m_table.clear();
#endif
	} else {
		std::unique_lock lock(m_mutex);
		if constexpr(k_cow) {
			if(is_shared()) {
				// No need to copy contents just to drop them.
				m_table = empty_contents();
			} else {
				m_table->clear();
			}
			m_entries_maybe_shared = false;
		} else {
			m_table.clear();
		}
		reset_cache();
	}
}

template<typename SyncPolicy>
size_t sinsp_fdtable_impl<SyncPolicy>::size() const {
	if constexpr(traits::k_use_folly_chm) {
		return m_table.size();
	} else {
		std::shared_lock lock(m_mutex);
		return tbl().size();
	}
}

template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::reset_cache() const {
	if constexpr(traits::k_use_folly_chm) {
#ifdef LIBSINSP_USE_FOLLY
		invalidate_tl_cache();
#endif
	} else {
		// Only the cache key is cleared here; m_last_accessed_fdinfo is intentionally
		// left untouched. Cache validity is keyed solely on m_last_accessed_fd (see
		// find_ref()), so clearing the key is enough to disarm the cache. Do not null
		// the shared_ptr to "tidy up": besides being unnecessary, it could free an
		// fdinfo that a raw pointer obtained earlier in the same event still points at.
		m_last_accessed_fd = -1;
	}
}

// Lazily resolves the device number of file entries coming from a proc scan.
// This is the one entry write allowed on the read-only lookup path: it is an
// idempotent, derived fill (same mount id resolves to the same device no
// matter which table triggers it), so performing it on an entry shared with
// other fd tables is safe and does not require copy-on-write.
//
// That holds only for an answer. A failed lookup must leave the mount id in
// place, or it would take the entry's last chance to ever resolve with it --
// and on a shared entry it would take it away from every other table too,
// including tables whose own tid can still be read.
template<typename SyncPolicy>
void sinsp_fdtable_impl<SyncPolicy>::lookup_device(fdinfo_t& fdi) const {
#ifndef _WIN32
	if(!m_params) {
		return;
	}
	if(m_params->m_sinsp_mode.is_offline() ||
	   (m_params->m_sinsp_mode.is_plugin() && !is_syscall_plugin_enabled())) {
		return;
	}

	if(m_tid != 0 && m_tid != static_cast<uint64_t>(-1) && fdi.is_file() && fdi.get_dev() == 0 &&
	   fdi.get_mount_id() != 0) {
		const auto dev =
		        scap_get_device_by_mount_id(m_params->m_scap_platform, m_tid, fdi.get_mount_id());
		if(dev != 0) {
			fdi.set_dev(dev);
			fdi.set_mount_id(0);  // resolved, don't ask again
		}
	}
#endif  // _WIN32
}

template<typename SyncPolicy>
std::shared_ptr<const typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::find(const int64_t fd) const {
	return find_ref(fd);
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::find_mut(const int64_t fd) {
	if constexpr(k_cow) {
		// Fast path: cache hit on an entry that is already private (its only
		// references are our slot and our cache). The paths that could move the
		// slot away from the cached entry all reset the cache key first.
		if(fd == m_last_accessed_fd && m_last_accessed_fd != -1 && !is_shared() &&
		   m_last_accessed_fdinfo.use_count() == 2) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_cached_fd_lookups();
			}
			return m_last_accessed_fdinfo;
		}

		detach_if_shared();

		const auto it = m_table->find(fd);
		if(it == m_table->end()) {
			if(m_params && m_params->m_sinsp_stats_v2) {
				m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_failed_fd_lookups();
			}
			return nullptr;
		}

		auto* fdinfo = slot_mut(it);

		if(m_params && m_params->m_sinsp_stats_v2 != nullptr) {
			m_params->m_sinsp_stats_v2->get_thread_counters().inc_n_noncached_fd_lookups();
		}
		m_last_accessed_fd = fd;
		m_last_accessed_fdinfo = it->second;
		lookup_device(*fdinfo);
		return it->second;
	} else {
		// Entries are never shared between tables: a lookup is enough.
		return find_ref(fd);
	}
}

template<typename SyncPolicy>
std::shared_ptr<typename sinsp_fdtable_impl<SyncPolicy>::fdinfo_t>
sinsp_fdtable_impl<SyncPolicy>::add(const int64_t fd, std::shared_ptr<fdinfo_t>&& fdinfo) {
	return add_ref(fd, std::move(fdinfo));
}

template<typename SyncPolicy>
std::unique_ptr<libsinsp::state::table_entry> sinsp_fdtable_impl<SyncPolicy>::new_entry() const {
	return m_params ? m_params->m_fdinfo_factory.create() : nullptr;
};

template<typename SyncPolicy>
std::shared_ptr<libsinsp::state::table_entry> sinsp_fdtable_impl<SyncPolicy>::get_entry(
        const int64_t& key) {
	// Conservative: entries handed to the plugin API are writable through
	// write_entry_field, so they must be private to this table at handout.
	//
	// The handle we hand out is an entry reference this table cannot tell apart
	// from another table's slot, so on a once-shared table every later writable
	// access to the same fd copies the entry again -- including a second
	// get_entry(), or a loop(), from the same plugin callback, which leaves the
	// earlier handle pointing at an orphaned copy. A handle is therefore only
	// good until the next writable access through the table, which is well
	// inside what it ever promised: it may already dangle across an erase, and
	// the accessed-entry bookkeeping asserts that plugins release their handles
	// before the callback returns.
	return find_mut(key);
}

template class sinsp_fdtable_impl<sync_policy_default>;
