# Fails unless the ndisrd driver payload ships next to vgww.exe.
# Invoked by the "driver_payload" ctest:
#   cmake -DPAYLOAD_DIR=<dir> -P scripts/check-driver-payload.cmake
# vgww's built-in installer (src/driver/installer.cpp) resolves
# ndisrd.sys / ndisrd_lwf.inf / ndisrd.cat from the executable directory, so a
# build whose output directory lacks any of them cannot install the driver.
if(NOT DEFINED PAYLOAD_DIR)
    message(FATAL_ERROR "PAYLOAD_DIR not provided")
endif()

foreach(name ndisrd.sys ndisrd_lwf.inf ndisrd.cat)
    if(NOT EXISTS "${PAYLOAD_DIR}/${name}")
        message(FATAL_ERROR "missing driver payload: ${PAYLOAD_DIR}/${name}")
    endif()
endforeach()

message(STATUS "driver payload present in ${PAYLOAD_DIR}")
