// ============================================================================
// random.cpp - Windows BCrypt CSPRNG helpers (see random.h).
// ============================================================================
#include "core/random.h"

#include <windows.h>
#include <bcrypt.h>

#include <vector>

namespace vgww {
    namespace core {

        namespace {
            constexpr size_t kMaxGenBytes = 1024 * 1024;  // ULONG guard
            constexpr size_t kMaxHexBytes = 4096;
        }  // namespace

        bool CsprngBytes(void* out, size_t n) noexcept {
            if (nullptr == out && 0 != n) {
                return false;
            }
            if (0 == n) {
                return true;
            }
            if (n > kMaxGenBytes) {
                return false;
            }
            const NTSTATUS st = ::BCryptGenRandom(
                nullptr, static_cast<PUCHAR>(out), static_cast<ULONG>(n),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            return 0 <= st;
        }

        std::string RandomHex(size_t byte_len) {
            static constexpr char kHex[] = "0123456789abcdef";
            std::string out;
            if (0 == byte_len || byte_len > kMaxHexBytes) {
                return out;
            }
            std::vector<uint8_t> buf(byte_len);
            if (!CsprngBytes(buf.data(), buf.size())) {
                return out;  // empty: caller must fail closed
            }
            out.reserve(byte_len * 2);
            for (const auto b : buf) {
                out.push_back(kHex[b >> 4]);
                out.push_back(kHex[b & 0xF]);
            }
            return out;
        }

    }  // namespace core
}  // namespace vgww
