// ============================================================================
// debug_state.h - CDP-style UI debug channel: control-state sink.
//
// UiDebugController serializes the element tree; per-control scalar state
// (value, caret, checked, expanded, selected index) is reported by each
// control through Element::debug_state(DebugStateSink&). The sink keeps
// element.h free of nlohmann: the controller implements the sink on top of
// nlohmann::json, and controls only depend on this tiny abstract header.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {

        namespace detail {
            /// Appends one Unicode scalar as 1-4 UTF-8 bytes (self-contained;
            /// no windows.h, no runtime dependency).
            inline void AppendUtf8(std::string& out, std::uint32_t c) {
                if (c < 0x80u) {
                    out.push_back(static_cast<char>(c));
                } else if (c < 0x800u) {
                    out.push_back(static_cast<char>(0xC0u | (c >> 6)));
                    out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
                } else if (c < 0x10000u) {
                    out.push_back(static_cast<char>(0xE0u | (c >> 12)));
                    out.push_back(static_cast<char>(0x80u | ((c >> 6) & 0x3Fu)));
                    out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
                } else {
                    out.push_back(static_cast<char>(0xF0u | (c >> 18)));
                    out.push_back(static_cast<char>(0x80u | ((c >> 12) & 0x3Fu)));
                    out.push_back(static_cast<char>(0x80u | ((c >> 6) & 0x3Fu)));
                    out.push_back(static_cast<char>(0x80u | (c & 0x3Fu)));
                }
            }
        }  // namespace detail

        /// UTF-16 (Windows wchar_t) -> UTF-8. Surrogate pairs (non-BMP
        /// scalars) are merged; an unpaired (lone) surrogate is emitted as the
        /// replacement character U+FFFD so the output is always valid UTF-8.
        inline std::string Utf16ToUtf8(std::wstring const& w) {
            std::string out;
            out.reserve(w.size() * 2);
            for (std::size_t i = 0; i < w.size(); ++i) {
                std::uint32_t c = static_cast<std::uint16_t>(w[i]);
                if (c >= 0xD800u && c <= 0xDBFFu) {
                    const std::uint32_t lo =
                        i + 1 < w.size()
                            ? static_cast<std::uint16_t>(w[i + 1])
                            : 0u;
                    if (lo >= 0xDC00u && lo <= 0xDFFFu) {
                        c = 0x10000u + ((c - 0xD800u) << 10) + (lo - 0xDC00u);
                        ++i;
                    } else {
                        c = 0xFFFDu;  // unpaired high surrogate
                    }
                } else if (c >= 0xDC00u && c <= 0xDFFFu) {
                    c = 0xFFFDu;      // unpaired low surrogate
                }
                detail::AppendUtf8(out, c);
            }
            return out;
        }

        /// Scalar-state sink passed to Element::debug_state. Implemented by the
        /// debug serializer; controls call DebugWrite for each leaf value.
        class DebugStateSink {
        public:
            virtual ~DebugStateSink() = default;
            virtual void WriteString(const char* key,
                                     const std::string& value) = 0;
            virtual void WriteBool(const char* key, bool value) = 0;
            virtual void WriteInt(const char* key, long long value) = 0;
            virtual void WriteDouble(const char* key, double value) = 0;
            /// Variable-length numeric state (e.g. a Table's resolved column
            /// widths). The sink owns the representation; controls pass the
            /// values in order.
            virtual void WriteDoubleArray(const char* key,
                                          const std::vector<double>& values) = 0;

        protected:
            DebugStateSink() = default;
        };

        /// ADL hook; controls write state via DebugWrite(s, "caret", caret_).
        template <typename T>
        void DebugWrite(DebugStateSink& sink, const char* key, const T& value) {
            // Fallback for state with no dedicated overload: it is stringified
            // via std::to_string and reported as a string value. The scalar
            // types controls use (bool/long long/double) and string types have
            // typed overloads below and never reach this path.
            sink.WriteString(key, std::to_string(value));
        }

        // Typed overloads: strings land via WriteString, scalars via their
        // typed sink methods, taking precedence over the fallback template.
        inline void DebugWrite(DebugStateSink& s, const char* k,
                               const std::string& v) { s.WriteString(k, v); }
        inline void DebugWrite(DebugStateSink& s, const char* k,
                               const char* v) { s.WriteString(k, v ? v : ""); }
        inline void DebugWrite(DebugStateSink& s, const char* k,
                               std::wstring const& v) {
            s.WriteString(k, Utf16ToUtf8(v));
        }
        inline void DebugWrite(DebugStateSink& s, const char* k, bool v) {
            s.WriteBool(k, v);
        }
        inline void DebugWrite(DebugStateSink& s, const char* k, long long v) {
            s.WriteInt(k, v);
        }
        inline void DebugWrite(DebugStateSink& s, const char* k, double v) {
            s.WriteDouble(k, v);
        }
        inline void DebugWrite(DebugStateSink& s, const char* k,
                               const std::vector<double>& v) {
            s.WriteDoubleArray(k, v);
        }

    }  // namespace ui
}  // namespace vgww
