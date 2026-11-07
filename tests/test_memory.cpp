// ============================================================================
// test_memory.cpp - Replaceable memory backend correctness.
//
// Covers: Malloc/Free round-trip across sizes, 64-byte alignment, Realloc
// content preservation + grow, Realloc(nullptr,n) == Malloc, and the backend
// name/version report.
// ============================================================================
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, \
                         __LINE__, #cond);                                 \
            return 1;                                                      \
        }                                                                  \
    } while (0)

#include "core/allocator.h"
#include "core/memory.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <new>
#include <type_traits>

namespace vgww {
    int RunTests() {
        // 1. Malloc round-trip with a range of sizes.
        for (const size_t size : {size_t(0), size_t(1), size_t(64), size_t(4097)}) {
            void* p = core::Malloc(size);
            CHECK(nullptr != p);
            core::Free(p);
        }

        // 2. Alignment: the backend guarantees std::max_align_t (16 bytes on
        //    x64). kMemoryAlignment (64) is a SIZE rounding policy, not a
        //    pointer-alignment promise (memory.h documents the distinction).
        {
            void* p = core::Malloc(257);
            CHECK(nullptr != p);
            CHECK(0 == (reinterpret_cast<uintptr_t>(p) %
                         alignof(std::max_align_t)));
            core::Free(p);
            // MemoryAlignSize semantics: 0 stays 0 (Malloc(0) must still be
            // non-null - the STL allocator's edge case), everything else
            // rounds up to the next 64-byte multiple.
            CHECK(0 == core::MemoryAlignSize(0));
            CHECK(64 == core::MemoryAlignSize(1));
            CHECK(64 == core::MemoryAlignSize(64));
            CHECK(128 == core::MemoryAlignSize(65));
            CHECK(nullptr != core::Malloc(0));

            // batch241: MemoryAlignSize is a pure rounding helper whose 0
            // output means "nothing to allocate" - satisfied by a genuine 0
            // request AND by an un-roundable (wrapping) request. The contract
            // that matters is on the allocation helpers: they must turn an
            // oversized request into a null return instead of handing back a
            // block sized for nothing.
            CHECK(0 == core::MemoryAlignSize(SIZE_MAX));
            CHECK(0 == core::MemoryAlignSize(SIZE_MAX - 1));
            CHECK(0 != core::MemoryAlignSize(SIZE_MAX - 63));
            CHECK(nullptr == core::Malloc(SIZE_MAX));
            CHECK(nullptr == core::Malloc(SIZE_MAX - 1));
            CHECK(nullptr == core::Realloc(nullptr, SIZE_MAX));
            // A legitimate zero request still allocates (the STL allocator
            // contract) - the guard must not turn it into a failure.
            CHECK(nullptr != core::Malloc(0));
            CHECK(nullptr != core::Realloc(nullptr, 0));
            // Oversized Realloc must leave the original block untouched.
            {
                void* keep = core::Malloc(64);
                CHECK(nullptr != keep);
                std::memcpy(keep, "KEEPME", 7);
                CHECK(nullptr == core::Realloc(keep, SIZE_MAX));
                CHECK(0 == std::memcmp(keep, "KEEPME", 7));
                core::Free(keep);
            }
        }

        // 3. Realloc preserves contents and grows the block.
        {
            void* p = core::Malloc(64);
            std::memcpy(p, "VGWW-MEMORY-POOL", 16);
            void* q = core::Realloc(p, 4096);
            CHECK(nullptr != q);
            CHECK(0 == std::memcmp(q, "VGWW-MEMORY-POOL", 16));
            core::Free(q);
        }

        // 4. Realloc(nullptr, n) behaves like Malloc.
        {
            void* p = core::Realloc(nullptr, 128);
            CHECK(nullptr != p);
            core::Free(p);
        }

        // 5. Backend name is a non-empty descriptive string.
        {
            const char* name = core::MemoryBackendName();
            CHECK(nullptr != name && 0 != name[0]);
            std::fprintf(stderr, "memcfg: backend=%s version=%s\n", name,
                         core::MemoryBackendVersion());
        }

        // 6. PoolAllocator drives std::vector / std::string end to end.
        {
            core::PoolVector<int> nums;
            for (int i = 0; i < 1024; ++i) nums.push_back(i * 3);
            int sum = 0;
            for (int n : nums) sum += n;
            CHECK(sum == 3 * (1023 * 1024) / 2);

            core::PoolString s;
            for (int i = 0; i < 100; ++i) s += "abcdefgh";
            CHECK(s.size() == 800);
            CHECK(0 == s.compare(0, 8, "abcdefgh"));
        }

        // 7. PoolMap keys/values.
        {
            core::PoolMap<int, std::string> m;
            m[7] = "seven";
            m[3] = "three";
            CHECK(m.size() == 2);
            CHECK("seven" == m[7]);
        }


        // 8. batch273: PoolAllocator's overflow guard. `n * sizeof(T)` must be
        //    rejected BEFORE the multiply, otherwise a huge `n` wraps and
        //    allocate() hands back a tiny block for a request the container
        //    believes is enormous. The STL passes `n` straight through, so
        //    calling allocate() directly is the only way to reach it.
        {
            core::PoolAllocator<uint64_t> alloc;
            const size_t max_n = (std::numeric_limits<size_t>::max)();
            // sizeof(uint64_t) == 8: max/8 succeeds, max/8 + 1 must throw.
            const size_t huge = max_n / sizeof(uint64_t) + 1;
            bool threw = false;
            try {
                (void)alloc.allocate(huge);
            } catch (const std::bad_alloc&) {
                threw = true;
            }
            CHECK(threw);

            // The largest n that CANNOT overflow is rejected by the BACKEND
            // (its own align-up wraps -> nullptr -> bad_alloc), not by the
            // multiply guard. Either way it must throw, never return a block.
            bool threw2 = false;
            try {
                (void)alloc.allocate(max_n / sizeof(uint64_t));
            } catch (const std::bad_alloc&) {
                threw2 = true;
            }
            CHECK(threw2);

            // A small request still works and is Free()-able (deallocate must
            // route to Free, not delete: the block came from Malloc).
            uint64_t* p = alloc.allocate(4);
            CHECK(nullptr != p);
            for (int i = 0; i < 4; ++i) p[i] = static_cast<uint64_t>(i);
            CHECK(p[3] == 3u);
            alloc.deallocate(p, 4);
        }

        // 9. batch273: the overflow guard must be per-element-size, not a
        //    fixed constant. A 1-byte T admits n == SIZE_MAX (no overflow),
        //    which the backend then refuses; a 4096-byte T rejects far
        //    earlier. Both must throw rather than wrap.
        {
            struct Big { char bytes[4096]; };
            core::PoolAllocator<char> byte_alloc;
            core::PoolAllocator<Big> big_alloc;
            const size_t max_n = (std::numeric_limits<size_t>::max)();

            // char: max_n / 1 + 1 wraps -> the guard must fire.
            bool threw_char = false;
            try { (void)byte_alloc.allocate(max_n); }
            catch (const std::bad_alloc&) { threw_char = true; }
            CHECK(threw_char);

            // Big: max_n / 4096 + 1 also wraps -> guard must fire.
            bool threw_big = false;
            try {
                (void)big_alloc.allocate(max_n / sizeof(Big) + 1);
            } catch (const std::bad_alloc&) { threw_big = true; }
            CHECK(threw_big);

            // Control: a modest Big request succeeds and is usable.
            Big* one = big_alloc.allocate(1);
            CHECK(nullptr != one);
            one->bytes[0] = 7;
            one->bytes[4095] = 9;
            CHECK(one->bytes[0] == 7 && one->bytes[4095] == 9);
            big_alloc.deallocate(one, 1);
        }

        // 10. batch273: PoolAllocator is stateless, so every instance compares
        //     EQUAL regardless of T - that is what lets containers move
        //     elements between rebind'ed allocators. A stateful comparison
        //     (returning false) would make std::vector's move-assign fall back
        //     to element-wise copy and silence the ==/!= contract.
        {
            core::PoolAllocator<int> a;
            core::PoolAllocator<int> b;
            core::PoolAllocator<double> c;
            CHECK(a == b);
            CHECK(!(a != b));
            CHECK(a == c);  // cross-type: always equal
            CHECK(!(a != c));
        }

        // 11. batch273: rebind must preserve the PoolAllocator template, else
        //     a container's internal node allocator would silently escape to
        //     the CRT heap and defeat the whole point of PoolVector.
        {
            using Rebound = core::PoolAllocator<int>::rebind<double>::other;
            static_assert(std::is_same<Rebound, core::PoolAllocator<double>>::value,
                          "rebind must map to PoolAllocator<U>");
            using VecRebound =
                std::allocator_traits<core::PoolAllocator<int>>::rebind_alloc<char>;
            static_assert(std::is_same<VecRebound, core::PoolAllocator<char>>::value,
                          "allocator_traits must see the same rebind");
            CHECK(true);  // the static_asserts above are the real test
        }

        std::fprintf(stderr, "memory: all checks passed\n");
        return 0;
    }
}  // namespace vgww

int main() {
    return vgww::RunTests();
}
