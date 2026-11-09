// ============================================================================
// console_log.cpp - stdout/stderr capture + bounded line ring (batch19 R3-2).
// ============================================================================
#include "ui/console_log.h"

#include "core/handler_guard.h"
#include "ui/pages/page_util.h"  // batch31 P0-1: the ONE UTF-8 Widen

#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

namespace vgww {
    namespace ui {
        namespace console_log {

            namespace {

                /// Bounded log history. 2000 lines is plenty for a debugging
                /// page and keeps the worst-case memory small.
                constexpr std::size_t kMaxLines = 2000;
                /// A partial line longer than this is folded immediately so a
                /// runaway writer cannot grow the pending buffer without bound.
                constexpr std::size_t kMaxPendingBytes = 64 * 1024;

                std::mutex g_line_mutex;
                std::deque<std::wstring> g_lines;
                std::uint64_t g_revision = 0;
                /// batch126: see DroppedLineCount().
                std::uint64_t g_dropped = 0;

                std::mutex g_install_mutex;
                bool g_installed = false;
                std::atomic<bool> g_stop{false};
                HANDLE g_read = nullptr;
                std::thread g_reader;
                /// Every descriptor that holds a duplicate of the pipe write
                /// end; Uninstall closes them all to give the reader EOF.
                std::vector<int> g_write_fds;

                /// batch31 P0-1: the console log lines are UTF-8 from the data
                /// plane; page_util.h's Widen is the single decoder (invalid
                /// bytes still fall back per-byte, never dropped).
                std::wstring WidenUtf8(const std::string& text) {
                    return Widen(text);
                }

                // P6: the disk log (same funnel as the ring buffer below).
                std::mutex g_file_mutex;
                std::FILE* g_file = nullptr;
                std::wstring g_log_path;
                std::size_t g_log_bytes = 0;
                std::size_t g_log_rollover = 5u * 1024u * 1024u;
                std::wstring g_log_dir_override;

                std::wstring DefaultLogDir() {
                    if (!g_log_dir_override.empty()) {
                        return g_log_dir_override;
                    }
                    wchar_t buffer[MAX_PATH * 2] = L"";
                    const DWORD n = ::GetEnvironmentVariableW(
                        L"LOCALAPPDATA", buffer,
                        static_cast<DWORD>(std::size(buffer)));
                    if (n > 0 && n < std::size(buffer)) {
                        return std::wstring(buffer) + L"\\VGWW\\logs";
                    }
                    wchar_t exe[MAX_PATH * 2] = L"";
                    const DWORD m = ::GetModuleFileNameW(nullptr, exe,
                                                        static_cast<DWORD>(
                                                            std::size(exe)));
                    if (m > 0) {
                        std::wstring path(exe);
                        const std::size_t cut = path.find_last_of(L"\\/");
                        if (cut != std::wstring::npos) {
                            path.resize(cut);
                        }
                        return path + L"\\logs";
                    }
                    return L"";
                }

                /// Opens (creating dirs) the log file, rolling an existing
                /// size-capped file to "vgww.log.1". Never throws.
                bool OpenLogFileNoThrow() {
                    std::lock_guard<std::mutex> lock(g_file_mutex);
                    if (g_file != nullptr) {
                        return true;
                    }
                    const std::wstring dir = DefaultLogDir();
                    if (dir.empty()) {
                        return false;
                    }
                    ::CreateDirectoryW(dir.c_str(), nullptr);
                    const std::wstring path = dir + L"\\vgww.log";
                    // batch120: _wfopen is the deprecated spelling (C4996).
                    // The real defect it hid: ftell() on a freshly opened
                    // append-mode stream reports 0, so a log left by a
                    // previous run looked EMPTY and the rollover budget
                    // restarted from zero - the file could reach roughly twice
                    // the configured limit before it rolled. Ask the file for
                    // its actual size instead.
                    // _wfsopen with an explicit _SH_DENYNO share mode is the
                    // non-deprecated spelling AND keeps the stream readable by
                    // other handles (a tail/log reader). _wfopen_s would have
                    // opened it exclusively and broken every concurrent reader,
                    // which is exactly what the disk-log tests detect.
                    g_file = ::_wfsopen(path.c_str(), L"ab", _SH_DENYNO);
                    if (nullptr == g_file) {
                        return false;
                    }
                    g_log_path = path;
                    ::fseek(g_file, 0, SEEK_END);
                    const long long size = ::_ftelli64(g_file);
                    g_log_bytes = size > 0 ? static_cast<std::size_t>(size) : 0;
                    return true;
                }

                void RollIfNeededLocked() {
                    if (g_file == nullptr || g_log_bytes < g_log_rollover) {
                        return;
                    }
                    const std::wstring path = g_log_path;
                    std::fclose(g_file);
                    g_file = nullptr;
                    const std::wstring rotated = path + L".1";
                    ::DeleteFileW(rotated.c_str());
                    ::MoveFileW(path.c_str(), rotated.c_str());
                    // batch120: same deprecation fix as the open path. A failed
                    // reopen leaves g_file null, which stops file logging while
                    // the in-memory ring keeps working (unchanged behaviour).
                    g_file = ::_wfsopen(path.c_str(), L"ab", _SH_DENYNO);
                    g_log_bytes = 0;
                }

                void TeeLineToFile(const std::string& utf8) noexcept {
                    std::lock_guard<std::mutex> lock(g_file_mutex);
                    if (g_file == nullptr) {
                        return;
                    }
                    RollIfNeededLocked();
                    if (g_file == nullptr) {
                        return;
                    }
                    std::fwrite(utf8.data(), 1, utf8.size(), g_file);
                    std::fwrite("\r\n", 1, 2, g_file);
                    std::fflush(g_file);
                    g_log_bytes += utf8.size() + 2;
                }

                void AppendLine(const std::string& utf8) {
                    std::wstring line = WidenUtf8(utf8);
                    TeeLineToFile(utf8);
                    std::lock_guard<std::mutex> lock(g_line_mutex);
                    g_lines.push_back(std::move(line));
                    while (g_lines.size() > kMaxLines) {
                        g_lines.pop_front();
                        ++g_dropped;
                    }
                    ++g_revision;
                }

                void Tee(HANDLE handle, const char* bytes, DWORD count) noexcept {
                    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
                        return;
                    }
                    DWORD written = 0;
                    ::WriteFile(handle, bytes, count, &written, nullptr);
                }

                /// Capture chunks whose fold path threw and was swallowed
                /// (telemetry/tests). The reader thread is a std::thread body
                /// and ReaderRun is noexcept: an escaping throw would call
                /// std::terminate and take the whole app down.
                std::atomic<uint64_t> g_reader_errors{0};
                /// Test seam: runs at the top of every folded chunk.
                std::function<void()> g_reader_probe;

                /// Folds one captured chunk into the ring (tee included).
                /// Firewalled: a throw costs this chunk, never the process.
                void ConsumeCapturedChunk(const char* data, size_t len,
                                          HANDLE tee,
                                          std::string& pending) noexcept {
                    ::vgww::core::InvokeHandlerGuarded(g_reader_errors, [&] {
                        if (g_reader_probe) {
                            g_reader_probe();
                        }
                        Tee(tee, data, static_cast<DWORD>(len));
                        pending.append(data, len);
                        std::size_t newline = 0;
                        while ((newline = pending.find('\n')) !=
                               std::string::npos) {
                            std::string line = pending.substr(0, newline);
                            pending.erase(0, newline + 1);
                            if (!line.empty() && line.back() == '\r') {
                                line.pop_back();
                            }
                            AppendLine(line);
                        }
                        if (pending.size() > kMaxPendingBytes) {
                            AppendLine(pending);
                            pending.clear();
                        }
                    });
                }

                void ReaderRun(HANDLE read_h, HANDLE tee) noexcept {
                    std::string pending;
                    char buffer[4096];
                    while (!g_stop.load(std::memory_order_relaxed)) {
                        DWORD got = 0;
                        if (!::ReadFile(read_h, buffer, sizeof(buffer), &got,
                                        nullptr) ||
                            got == 0) {
                            break;  // pipe closed / broken
                        }
                        // Keep the interactive --console window readable. The
                        // merged pipe cannot tell stdout from stderr, so the
                        // chunk is written to the console exactly ONCE (audit
                        // B F2: teeing to both console handles duplicated
                        // every line); a nil handle (GUI double-click) is a
                        // no-op.
                        ConsumeCapturedChunk(buffer, got, tee, pending);
                    }
                    if (!pending.empty()) {
                        ::vgww::core::InvokeHandlerGuarded(g_reader_errors, [&] {
                            if (pending.back() == '\r') {
                                pending.pop_back();
                            }
                            AppendLine(pending);
                        });
                    }
                }

            }  // namespace

            bool Install() {
                std::lock_guard<std::mutex> lock(g_install_mutex);
                if (g_installed) {
                    return true;
                }

                // P6: open the disk log up front and announce its path as the
                // first captured line, so the user can find the file.
                if (OpenLogFileNoThrow() && !g_log_path.empty()) {
                    const std::wstring wide = L"log file: " + g_log_path;
                    std::string utf8;
                    const int need = ::WideCharToMultiByte(
                        CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                        nullptr, 0, nullptr, nullptr);
                    if (need > 0) {
                        utf8.resize(static_cast<std::size_t>(need), '\0');
                        ::WideCharToMultiByte(
                            CP_UTF8, 0, wide.c_str(),
                            static_cast<int>(wide.size()), utf8.data(), need,
                            nullptr, nullptr);
                        AppendLine(utf8);
                    }
                }

                SECURITY_ATTRIBUTES sa{};
                sa.nLength = sizeof(sa);
                sa.bInheritHandle = TRUE;
                HANDLE read_h = nullptr;
                HANDLE write_h = nullptr;
                if (!::CreatePipe(&read_h, &write_h, &sa, 0)) {
                    return false;
                }
                ::SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0);
                // audit B F3: the write end must not leak into child processes
                // (a child inheriting it would keep the pipe open past
                // Uninstall, delaying the reader's EOF).
                ::SetHandleInformation(write_h, HANDLE_FLAG_INHERIT, 0);

                const int write_fd = ::_open_osfhandle(
                    reinterpret_cast<intptr_t>(write_h),
                    _O_WRONLY | _O_BINARY);
                if (write_fd < 0) {
                    ::CloseHandle(read_h);
                    ::CloseHandle(write_h);
                    return false;
                }

                // Capture the pre-dup handles for the console tee (valid when
                // launched from cmd with --console; nil on a double-click).
                const HANDLE orig_out = ::GetStdHandle(STD_OUTPUT_HANDLE);
                const HANDLE orig_err = ::GetStdHandle(STD_ERROR_HANDLE);
                const auto valid = [](HANDLE h) {
                    return h != nullptr && h != INVALID_HANDLE_VALUE;
                };
                // One tee target only: prefer stdout, else stderr (audit B F2).
                const HANDLE tee =
                    valid(orig_out) ? orig_out : (valid(orig_err) ? orig_err
                                                                   : nullptr);

                // A GUI-subsystem process with no console starts with the
                // stdout/stderr FILE* streams UNATTACHED (fileno == -2), so a
                // plain _dup2(fd, 1/2) fixes the descriptor table but leaves
                // printf writing into a dead stream. Attach each stream to a
                // real file (NUL) first, then dup the pipe onto *its own*
                // descriptor (plus 1/2 for raw _write users).
                const auto rebind = [&](FILE* stream) {
                    int fd = ::_fileno(stream);
                    if (fd < 0) {
                        FILE* f = nullptr;
                        ::freopen_s(&f, "NUL", "w", stream);
                        fd = ::_fileno(stream);
                    }
                    if (fd >= 0) {
                        ::_dup2(write_fd, fd);
                        ::_setmode(fd, _O_BINARY);
                        g_write_fds.push_back(fd);
                    }
                };
                rebind(stdout);
                rebind(stderr);
                ::_dup2(write_fd, 1);
                ::_dup2(write_fd, 2);
                ::_setmode(1, _O_BINARY);
                ::_setmode(2, _O_BINARY);
                g_write_fds.push_back(1);
                g_write_fds.push_back(2);
                // A pipe makes CRT stdout fully buffered, so printf lines
                // would only surface on flush/exit; the console page needs
                // them as they happen. stderr was already unbuffered.
                ::setvbuf(stdout, nullptr, _IONBF, 0);
                ::setvbuf(stderr, nullptr, _IONBF, 0);
                std::sort(g_write_fds.begin(), g_write_fds.end());
                g_write_fds.erase(
                    std::unique(g_write_fds.begin(), g_write_fds.end()),
                    g_write_fds.end());
                ::_close(write_fd);  // the dup'ed descriptors stay open

                g_read = read_h;
                g_stop.store(false, std::memory_order_relaxed);
                g_installed = true;
                g_reader = std::thread(ReaderRun, read_h, tee);
                return true;
            }

            void Uninstall() noexcept {
                std::thread reader;
                HANDLE read_h = nullptr;
                {
                    std::lock_guard<std::mutex> lock(g_install_mutex);
                    if (!g_installed) {
                        return;
                    }
                    g_stop.store(true, std::memory_order_relaxed);
                    // Closing every duplicated write end makes ReadFile see
                    // EOF, which wakes the reader without CancelSynchronousIo.
                    for (const int fd : g_write_fds) {
                        ::_close(fd);
                    }
                    g_write_fds.clear();
                    read_h = g_read;
                    g_read = nullptr;
                    g_installed = false;
                    reader = std::move(g_reader);
                }
                if (reader.joinable()) {
                    reader.join();
                }
                if (read_h != nullptr) {
                    ::CloseHandle(read_h);
                }
            }

            bool installed() noexcept {
                std::lock_guard<std::mutex> lock(g_install_mutex);
                return g_installed;
            }

            std::uint64_t Revision() noexcept {
                std::lock_guard<std::mutex> lock(g_line_mutex);
                return g_revision;
            }

            std::uint64_t DroppedLineCount() noexcept {
                std::lock_guard<std::mutex> lock(g_line_mutex);
                return g_dropped;
            }

            std::vector<std::wstring> Snapshot() {
                std::lock_guard<std::mutex> lock(g_line_mutex);
                return std::vector<std::wstring>(g_lines.begin(),
                                                 g_lines.end());
            }

            std::size_t LineCount() noexcept {
                std::lock_guard<std::mutex> lock(g_line_mutex);
                return g_lines.size();
            }

            void AppendForTest(const std::string& utf8) {
                std::size_t start = 0;
                for (std::size_t i = 0; i <= utf8.size(); ++i) {
                    if (i == utf8.size() || utf8[i] == '\n') {
                        if (i == utf8.size() && start == utf8.size()) {
                            break;
                        }
                        AppendLine(utf8.substr(start, i - start));
                        start = i + 1;
                    }
                }
            }

            void HandleCapturedChunkForTest(const std::string& chunk) {
                static thread_local std::string scratch;
                ConsumeCapturedChunk(chunk.data(), chunk.size(), nullptr,
                                     scratch);
                scratch.clear();
            }

            void SetReaderProbeForTest(std::function<void()> probe) {
                g_reader_probe = std::move(probe);
            }

            std::uint64_t ReaderErrorCountForTest() noexcept {
                return g_reader_errors.load(std::memory_order_relaxed);
            }

            void AppendAuditLine(const std::string& utf8) {
                // batch22 B4: privileged operations are recorded in the same
                // ring used by the native console / web console page / disk log.
                AppendLine("[audit] " + utf8);
            }

            void ClearForTest() noexcept {
                std::lock_guard<std::mutex> lock(g_line_mutex);
                g_lines.clear();
                g_dropped = 0;
                ++g_revision;
            }

        namespace {
            bool Win32ClipboardRead(std::wstring& out) {
                out.clear();
                if (FALSE == ::IsClipboardFormatAvailable(CF_UNICODETEXT)) {
                    // No text format on the clipboard: a real empty, not a
                    // failure.
                    return true;
                }
                if (!::OpenClipboard(nullptr)) {
                    return false;
                }
                bool ok = true;
                HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
                if (data != nullptr) {
                    const wchar_t* src =
                        static_cast<const wchar_t*>(::GlobalLock(data));
                    if (src != nullptr) {
                        out.assign(src);
                        ::GlobalUnlock(data);
                    } else {
                        ok = false;
                    }
                } else {
                    ok = false;
                }
                ::CloseClipboard();
                return ok;
            }

            bool Win32ClipboardWrite(const std::wstring& text) {
                if (!::OpenClipboard(nullptr)) {
                    return false;
                }
                bool ok = false;
                if (::EmptyClipboard()) {
                    const std::size_t bytes =
                        (text.size() + 1) * sizeof(wchar_t);
                    if (HGLOBAL mem = ::GlobalAlloc(GMEM_MOVEABLE, bytes)) {
                        if (void* dst = ::GlobalLock(mem)) {
                            std::memcpy(dst, text.c_str(), bytes);
                            ::GlobalUnlock(mem);
                            if (::SetClipboardData(CF_UNICODETEXT, mem) !=
                                nullptr) {
                                ok = true;
                                mem = nullptr;  // ownership transferred
                            }
                        }
                        if (mem != nullptr) {
                            ::GlobalFree(mem);
                        }
                    }
                }
                ::CloseClipboard();
                return ok;
            }

            std::function<bool(std::wstring&)>& ClipboardReader() {
                static std::function<bool(std::wstring&)> reader =
                    Win32ClipboardRead;
                return reader;
            }

            std::function<bool(const std::wstring&)>& ClipboardWriter() {
                static std::function<bool(const std::wstring&)> writer =
                    Win32ClipboardWrite;
                return writer;
            }
        }  // namespace

        std::wstring LogFilePath() {
            std::lock_guard<std::mutex> lock(g_file_mutex);
            return g_log_path;
        }

        void SetLogDirForTest(const std::wstring& dir) {
            std::lock_guard<std::mutex> lock(g_file_mutex);
            g_log_dir_override = dir;
        }

        void SetLogRolloverBytesForTest(std::size_t bytes) {
            std::lock_guard<std::mutex> lock(g_file_mutex);
            g_log_rollover = bytes;
        }

        bool OpenLogFileForTest() noexcept { return OpenLogFileNoThrow(); }

        void CloseLogFileForTest() noexcept {
            std::lock_guard<std::mutex> lock(g_file_mutex);
            if (g_file != nullptr) {
                std::fclose(g_file);
                g_file = nullptr;
            }
            g_log_path.clear();
            g_log_bytes = 0;
        }

        void SetClipboardWriterForTest(
            std::function<bool(const std::wstring&)> writer) {
            ClipboardWriter() = writer ? std::move(writer) : Win32ClipboardWrite;
        }

        bool CopyToClipboard(const std::wstring& text) {
            return ClipboardWriter()(text);
        }

        void SetClipboardReaderForTest(
            std::function<bool(std::wstring&)> reader) {
            ClipboardReader() = reader ? std::move(reader) : Win32ClipboardRead;
        }

        bool ReadClipboardText(std::wstring& out) {
            return ClipboardReader()(out);
        }

        std::wstring SnapshotText() {
            const std::vector<std::wstring> lines = Snapshot();
            std::wstring out;
            for (std::size_t i = 0; i < lines.size(); ++i) {
                if (i != 0) {
                    out += L"\r\n";
                }
                out += lines[i];
            }
            return out;
        }

        }  // namespace console_log
    }  // namespace ui
}  // namespace vgww
