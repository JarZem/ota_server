# JarZem Secure OTA post-project hook. Include this after project(...).
get_filename_component(JARZEM_OTA_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(JARZEM_OTA_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

if(DEFINED PYTHON AND EXISTS "${PYTHON}")
    set(JARZEM_OTA_PUBLISH_PYTHON "${PYTHON}")
else()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(JARZEM_OTA_PUBLISH_PYTHON "${Python3_EXECUTABLE}")
endif()

add_custom_target(jarzem_ota_publish ALL
    COMMAND "${JARZEM_OTA_PUBLISH_PYTHON}"
            "${JARZEM_OTA_REPO_ROOT}/tools/esp_ota/publish_firmware.py"
            --project "${JARZEM_OTA_PROJECT_ROOT}"
            --build "${CMAKE_BINARY_DIR}"
            --project-name "${CMAKE_PROJECT_NAME}"
    DEPENDS app
    COMMENT "Publishing firmware to JarZem OTA server"
    VERBATIM
)
