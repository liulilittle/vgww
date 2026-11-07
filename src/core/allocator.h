// ============================================================================
// allocator.h - STL allocator backed by the replaceable memory backend.
//
// PoolAllocator<T> routes every STL allocation for the container it is bound
// to through core::Malloc/core::Free, letting the compiled-in backend
// (jemalloc or CRT) service heap traffic. PoolVector / PoolString / PoolMap
// are drop-in aliases over the default STL containers, so existing code can
// opt into the pool with a one-word type change.
// ============================================================================
#pragma once

#include "core/memory.h"

#include <cstddef>
#include <limits>
#include <map>
#include <new>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace vgww {
    namespace core {

        /// State-free, always-equal allocator backed by core::Malloc/Free.
        template <typename T>
        struct PoolAllocator {
            using value_type = T;

            PoolAllocator() noexcept = default;

            template <typename U>
            PoolAllocator(const PoolAllocator<U>&) noexcept {}

            T* allocate(size_t n) {
                if (n > (std::numeric_limits<size_t>::max)() / sizeof(T)) {
                    throw std::bad_alloc();
                }
                void* p = Malloc(n * sizeof(T));
                if (nullptr == p) throw std::bad_alloc();
                return static_cast<T*>(p);
            }

            void deallocate(T* p, size_t) noexcept {
                Free(p);
            }

            template <typename U>
            struct rebind {
                using other = PoolAllocator<U>;
            };

            template <typename U>
            bool operator==(const PoolAllocator<U>&) const noexcept {
                return true;
            }
            template <typename U>
            bool operator!=(const PoolAllocator<U>&) const noexcept {
                return false;
            }
        };

        template <typename T>
        using PoolVector = std::vector<T, PoolAllocator<T>>;

        using PoolString =
            std::basic_string<char, std::char_traits<char>, PoolAllocator<char>>;

        template <typename K, typename V, typename Cmp = std::less<K>>
        using PoolMap =
            std::map<K, V, Cmp, PoolAllocator<std::pair<const K, V>>>;

    }  // namespace core
}  // namespace vgww
