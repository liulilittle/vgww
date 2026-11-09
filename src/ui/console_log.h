// ============================================================================
// console_log.h - process stdout/stderr capture for the native console page
// (batch19 R3-2).
//
// The program prints through plain CRT stdio (printf/fprintf) in hundreds of
// places; introducing a full logging sink would touch every call site. Instead
// Install() dups a pipe onto CRT fds 1/2, a reader thread drains it, and the
// bytes are folded into a bounded, mutex-protected ring of wide text lines that
// the console page polls. Install() is a no-op in headless/console-only runs -
// the capture only exists to feed the UI page.
//
// Lifecycle: Install() at UI startup (after any --console EnsureConsole, so the
// original console handles exist for the tee), Uninstall() before the process
// returns. Uninstall closes the CRT write ends so the reader sees EOF and joins
// the thread; it is idempotent and safe to call when never installed.
// ============================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vgww {
    namespace ui {
        namespace console_log {

            /// Redirects CRT stdout/stderr through the capture pipe and starts
            /// the reader thread. Idempotent. Returns false when the pipe/dup
            /// could not be created (the UI then simply shows an empty log;
            /// stdout keeps working).
            bool Install();

            /// Stops the reader thread and closes the pipe. Idempotent.
            void Uninstall() noexcept;

            /// True while the capture pipe is installed.
            bool installed() noexcept;

            /// Monotone counter bumped on every append/clear. A poller can
            /// skip the Snapshot() copy while it is unchanged (audit B F5).
            std::uint64_t Revision() noexcept;

            /// batch126: cumulative lines evicted by the bounded ring (the
            /// oldest first). A dropped line - possibly an [audit] record -
            /// must not be a silent loss.
            std::uint64_t DroppedLineCount() noexcept;

            /// Thread-safe snapshot of the captured lines (oldest first).
            std::vector<std::wstring> Snapshot();

            /// Number of buffered lines (test/debug seam).
            std::size_t LineCount() noexcept;

            /// Test seam: appends one UTF-8 line through the exact same fold
            /// path the reader thread uses (no process-wide redirection).
            void AppendForTest(const std::string& utf8);

            /// Test seam: runs one captured CHUNK through the reader thread's
            /// exact fold path (tee, line splitting, overflow fold) without
            /// redirecting the process streams.
            void HandleCapturedChunkForTest(const std::string& chunk);

            /// Test seam: runs inside the folded-chunk body; throwing proves
            /// the reader thread's firewall holds.
            void SetReaderProbeForTest(std::function<void()> probe);

            /// Chunk bodies whose exception was swallowed by the firewall
            /// (telemetry/tests).
            std::uint64_t ReaderErrorCountForTest() noexcept;

            /// batch22 B4: appends one privileged-operation audit line to the
            /// same ring (so it is visible in the native console, the web
            /// console page and the on-disk log). Never carries secrets.
            void AppendAuditLine(const std::string& utf8);

            /// Test seam: clears the ring buffer.
            void ClearForTest() noexcept;

            /// batch20 item 7: writes `text` to the system clipboard (CF_UNICODETEXT).
            /// Returns false when the clipboard could not be opened/owned.
            bool CopyToClipboard(const std::wstring& text);

            /// Test seam: replaces the clipboard writer (default = the Win32
            /// implementation). Passing nullptr restores the default.
            void SetClipboardWriterForTest(std::function<bool(const std::wstring&)> writer);

            /// batch288: reads CF_UNICODETEXT. Returns false ONLY when the clipboard
            /// could not be opened or its data could not be locked (transient
            /// contention). `out` empty with true means "no text on the clipboard",
            /// which is not an error. The old read had no failure channel, so Ctrl+V
            /// looked like a no-op whenever another process held the clipboard.
            bool ReadClipboardText(std::wstring& out);

            /// Test seam: replaces the clipboard reader (default = the Win32
            /// implementation). Passing nullptr restores the default.
            void SetClipboardReaderForTest(std::function<bool(std::wstring&)> reader);

            /// The console text as one CRLF-joined string (what the copy button copies).
            std::wstring SnapshotText();

            /// batch20 P6: the SAME captured output the console shows is teed line by line
            /// to a local log file (append across sessions, size-rolled). Default path:
            /// %LOCALAPPDATA%\VGWW\logs\vgww.log (falling back to <exe>\logs\vgww.log).
            /// A failure never affects the app (the console simply has no file).
            /// Returns the active log path (empty when unavailable).
            std::wstring LogFilePath();

            /// Test seams: redirect the log dir and force a small rollover so the
            /// rename-on-size behaviour is testable, then open/close the file directly
            /// (the capture pipe is not involved).
            void SetLogDirForTest(const std::wstring& dir);
            void SetLogRolloverBytesForTest(std::size_t bytes);
            bool OpenLogFileForTest() noexcept;
            void CloseLogFileForTest() noexcept;

        }  // namespace console_log
    }  // namespace ui
}  // namespace vgww
