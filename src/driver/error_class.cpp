// ============================================================================
// error_class.cpp - driver fault classifier (see error_class.h).
// ============================================================================
#include "driver/error_class.h"

namespace vgww {
    namespace driver {

        DriverFault ClassifyDriverFault(const std::string& text) {
            if (text.empty()) {
                return DriverFault::None;
            }
            if (text.find("ndisrd driver not installed") != std::string::npos ||
                text.find("WinpkFilter missing") != std::string::npos) {
                return DriverFault::DriverMissing;
            }
            if (text.find("access denied opening") != std::string::npos) {
                return DriverFault::AccessDenied;
            }
            if (text.find("no adapter matches") != std::string::npos) {
                return DriverFault::AdapterMissing;
            }
            return DriverFault::Other;
        }

    }  // namespace driver
}  // namespace vgww
