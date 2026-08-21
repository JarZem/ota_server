# JarZem Secure OTA post-project hook. Include this after project(...).
get_filename_component(JARZEM_OTA_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(JARZEM_OTA_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

# Transparent Zigbee integration. Existing project code keeps calling the
# Espressif APIs; GNU ld redirects those two calls through the OTA component.
idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=esp_zb_device_register" APPEND)
idf_build_set_property(LINK_OPTIONS "-Wl,--wrap=esp_zb_core_action_handler_register" APPEND)

if(DEFINED PYTHON AND EXISTS "${PYTHON}")
    set(JARZEM_OTA_PYTHON "${PYTHON}")
else()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(JARZEM_OTA_PYTHON "${Python3_EXECUTABLE}")
endif()

# Produce one self-contained converter directory. The project wrapper and
# project-only converter stay in the application repository; OTA converter
# code always comes from this pinned submodule revision.
add_custom_target(jarzem_ota_z2m_bundle ALL
    COMMAND "${JARZEM_OTA_PYTHON}"
            "${JARZEM_OTA_REPO_ROOT}/tools/esp_ota/prepare_z2m_bundle.py"
            --project "${JARZEM_OTA_PROJECT_ROOT}"
            --submodule "${JARZEM_OTA_REPO_ROOT}"
            --output "${CMAKE_BINARY_DIR}/zigbee2mqtt"
    COMMENT "Preparing Zigbee2MQTT converter bundle"
    VERBATIM
)

# A successful application build is immediately published to the OTA server.
# Authentication uses the already installed CA-signed device identity; the
# device private key is used locally to sign the upload and is never sent.
add_custom_target(jarzem_ota_publish ALL
    COMMAND "${JARZEM_OTA_PYTHON}"
            "${JARZEM_OTA_REPO_ROOT}/tools/esp_ota/publish_firmware.py"
            --project "${JARZEM_OTA_PROJECT_ROOT}"
            --build "${CMAKE_BINARY_DIR}"
            --project-name "${CMAKE_PROJECT_NAME}"
    DEPENDS app jarzem_ota_z2m_bundle
    COMMENT "Publishing firmware to JarZem OTA server"
    VERBATIM
)
