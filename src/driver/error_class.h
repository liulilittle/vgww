// ============================================================================
// error_class.h - single source of truth for classifying dataplane driver
// failures from error text (batch 16 F1).
//
// The elevation/repair decisions in main.cpp and the UI banner mapping in
// ui/app.cpp used to match free-text substrings independently (batch16 audit
// D4): editing a literal in ndisrd_client.cpp silently broke both chains.
// Both consumers now classify through this pure function; the literal list
// below is the only place in the product that matches driver error text.
// ============================================================================
#pragma once

#include <string>

namespace vgww {
    namespace driver {

        /// Classified failure of the ndisrd dataplane path.
        enum class DriverFault {
            None,           ///< empty text: nothing to classify
            DriverMissing,  ///< device/service absent (ndisrd not installed)
            AccessDenied,   ///< device exists but the open was denied (DACL)
            AdapterMissing, ///< driver up, but no NIC matched the adapter hint
            Other,          ///< anything else (surfaced verbatim/generic)
        };

        /// Pure, side-effect free. Anchors on the literals produced by
        /// ndisrd_client.cpp ("ndisrd driver not installed", "WinpkFilter
        /// missing", "access denied opening \\\\.\\Ndisrd") and
        /// dataplane.cpp ("no adapter matches").
        DriverFault ClassifyDriverFault(const std::string& text);

    }  // namespace driver
}  // namespace vgww
