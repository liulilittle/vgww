// ============================================================================
// random.h - Cryptographically secure randomness helpers.
//
// The auth token that gates the whole management API must be unguessable.
// std::rand/dev_random on some toolchains only seed 32 bits - enough for a
// LAN host to brute-force over minutes - so tokens are drawn directly from
// the OS CSPRNG (BCryptGenRandom), never through a PRNG seeded once.
// ============================================================================
#pragma once

#include <cstddef>
#include <string>

namespace vgww {
    namespace core {

        /// Fills `out` with `n` bytes from the OS CSPRNG. Returns false only
        /// on failure (n = 0 succeeds). Bounded to 1 MiB per call.
        bool CsprngBytes(void* out, size_t n) noexcept;

        /// Returns `byte_len` (hex-encoded, so 2*byte_len characters) of
        /// CSPRNG-derived hex; empty on failure.
        std::string RandomHex(size_t byte_len);

    }  // namespace core
}  // namespace vgww
