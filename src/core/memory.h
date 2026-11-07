// ============================================================================
// memory.h - Process-wide memory backend switch.
//
// Compiled-time switch (openppp2 style): when VGWW_JEMALLOC is defined every
// allocation routes to jemalloc; otherwise it routes to the CRT heap. The
// switch is decided at build time (< 0.1% of instructions), so the data path
// carries zero indirection and no virtual dispatch.
//
// Allocation SIZES are rounded up to kMemoryAlignment. Pointer alignment is
// the system allocator's guarantee (std::max_align_t, 16 bytes on x64), NOT
// kMemoryAlignment: malloc/realloc cannot promise 64-byte alignment, and no
// caller relies on more than the standard guarantee.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdlib>

namespace vgww {
    namespace core {

        /// Allocation size granularity (bytes). 64 keeps large blocks
        /// cache-line sized; it is NOT a pointer-alignment guarantee (see the
        /// header comment).
        inline constexpr size_t kMemoryAlignment = 64;

        /// Aligns a size up to kMemoryAlignment. Returns 0 for input 0 (the
        /// caller's 0 semantics pass through) and, for any non-zero size that
        /// cannot be rounded up without wrapping, returns 0 as well - the
        /// allocation helpers below turn that into a null return instead of
        /// handing back a block sized for nothing.
        inline constexpr size_t MemoryAlignSize(size_t size) noexcept {
            // (size + align - 1) wraps when size > SIZE_MAX - (align - 1);
            // a plain `& ~(align-1)` would then produce a small (often 0)
            // value for a huge request.
            if (size > SIZE_MAX - (kMemoryAlignment - 1)) {
                return 0;
            }
            return (size + kMemoryAlignment - 1) & ~(kMemoryAlignment - 1);
        }

#if defined(VGWW_JEMALLOC)
        // vcpkg's Windows jemalloc build does not carry a usable
        // <jemalloc/jemalloc.h> C ABI without extra build hooks, so declare
        // the entry points directly (same approach as openppp2's stdafx.h).
        extern "C" {
            void* je_malloc(size_t size);
            void* je_realloc(void* ptr, size_t size);
            void je_free(void* ptr);
        }

        inline void* Malloc(size_t size) noexcept {
            const size_t aligned = MemoryAlignSize(size);
            if (0 != size && 0 == aligned) {
                return nullptr;  // oversized: refuse instead of allocating 0
            }
            return je_malloc(aligned);
        }

        inline void* Realloc(void* p, size_t size) noexcept {
            const size_t aligned = MemoryAlignSize(size);
            if (0 != size && 0 == aligned) {
                return nullptr;  // oversized: leave `p` untouched
            }
            return je_realloc(p, aligned);
        }

        inline void Free(void* p) noexcept {
            if (p) je_free(p);
        }

        inline const char* MemoryBackendName() noexcept { return "jemalloc"; }
        inline const char* MemoryBackendVersion() noexcept { return "5.3.0"; }
#else
        inline void* Malloc(size_t size) noexcept {
            const size_t aligned = MemoryAlignSize(size);
            if (0 != size && 0 == aligned) {
                return nullptr;  // oversized: refuse instead of allocating 0
            }
            return std::malloc(aligned);
        }

        inline void* Realloc(void* p, size_t size) noexcept {
            const size_t aligned = MemoryAlignSize(size);
            if (0 != size && 0 == aligned) {
                return nullptr;  // oversized: leave `p` untouched
            }
            return std::realloc(p, aligned);
        }

        inline void Free(void* p) noexcept {
            std::free(p);
        }

        inline const char* MemoryBackendName() noexcept { return "crt"; }
        inline const char* MemoryBackendVersion() noexcept { return "ucrt"; }
#endif

    }  // namespace core
}  // namespace vgww
