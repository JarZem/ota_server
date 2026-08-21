set(JARZEM_OTA_CREDENTIAL_DIR "${PROJECT_DIR}/device_credentials")
set(JARZEM_OTA_DEVICE_CERT_SOURCE "${JARZEM_OTA_CREDENTIAL_DIR}/device_cert.pem")
set(JARZEM_OTA_DEVICE_KEY_SOURCE "${JARZEM_OTA_CREDENTIAL_DIR}/device_private.pem")
set(JARZEM_OTA_ROOT_CA_SOURCE "${JARZEM_OTA_CREDENTIAL_DIR}/root_ca_cert.pem")
set(JARZEM_OTA_SERVER_CERT_SOURCE "${JARZEM_OTA_CREDENTIAL_DIR}/ota_server_cert.pem")

foreach(_credential IN ITEMS
        "${JARZEM_OTA_DEVICE_CERT_SOURCE}"
        "${JARZEM_OTA_DEVICE_KEY_SOURCE}"
        "${JARZEM_OTA_ROOT_CA_SOURCE}"
        "${JARZEM_OTA_SERVER_CERT_SOURCE}")
    if(NOT EXISTS "${_credential}")
        message(FATAL_ERROR
            "JarZem Secure OTA identity is incomplete: ${_credential} is missing. "
            "Builds never generate or replace an installed device identity. Run the installer for a new project, or restore the original identity files.")
    endif()
endforeach()

# Copy credentials to stable filenames in this component's build directory.
# ESP-IDF derives linker symbols from the embedded filename; keeping these
# basenames stable guarantees _binary_device_cert_pem_start etc. regardless
# of where the application repository lives on disk.
set(JARZEM_OTA_DEVICE_CERT "${CMAKE_CURRENT_BINARY_DIR}/device_cert.pem")
set(JARZEM_OTA_DEVICE_KEY "${CMAKE_CURRENT_BINARY_DIR}/device_private.pem")
set(JARZEM_OTA_ROOT_CA "${CMAKE_CURRENT_BINARY_DIR}/root_ca_cert.pem")
set(JARZEM_OTA_SERVER_CERT "${CMAKE_CURRENT_BINARY_DIR}/ota_server_cert.pem")
set(JARZEM_OTA_CA_BUNDLE "${CMAKE_CURRENT_BINARY_DIR}/ota_server_ca_bundle.pem")

configure_file("${JARZEM_OTA_DEVICE_CERT_SOURCE}" "${JARZEM_OTA_DEVICE_CERT}" COPYONLY)
configure_file("${JARZEM_OTA_DEVICE_KEY_SOURCE}" "${JARZEM_OTA_DEVICE_KEY}" COPYONLY)
configure_file("${JARZEM_OTA_ROOT_CA_SOURCE}" "${JARZEM_OTA_ROOT_CA}" COPYONLY)
configure_file("${JARZEM_OTA_SERVER_CERT_SOURCE}" "${JARZEM_OTA_SERVER_CERT}" COPYONLY)

file(READ "${JARZEM_OTA_ROOT_CA_SOURCE}" _root_ca_content)
file(READ "${JARZEM_OTA_SERVER_CERT_SOURCE}" _server_cert_content)
if(_root_ca_content MATCHES "PRIVATE KEY" OR _server_cert_content MATCHES "PRIVATE KEY")
    message(FATAL_ERROR "JarZem Secure OTA public trust bundle unexpectedly contains a private key")
endif()
file(WRITE "${JARZEM_OTA_CA_BUNDLE}" "${_root_ca_content}\n${_server_cert_content}\n")

idf_component_register(
    SRCS
        "src/jarzem_secure_ota.c"
        "src/device_credentials.c"
        "src/device_credentials_verify.c"
        "src/device_identity.c"
        "src/ota_component_storage.c"
        "src/ota_config.c"
        "src/ota_secure_session.c"
        "src/ota_check_auth.c"
        "src/ota_wifi.c"
        "src/ota_service_runtime.c"
        "src/zigbee_ota_cluster.c"
        "src/zigbee_ota_control.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private"
    REQUIRES
        esp_driver_gpio
        esp_timer
        esp_http_client
        esp_wifi
        esp_phy
        esp_netif
        esp_event
        esp_coex
        esp_hw_support
        ieee802154
        mbedtls
        nvs_flash
        app_update
        espressif__esp-zigbee-lib
    EMBED_TXTFILES
        "${JARZEM_OTA_DEVICE_CERT}"
        "${JARZEM_OTA_DEVICE_KEY}"
        "${JARZEM_OTA_ROOT_CA}"
        "${JARZEM_OTA_SERVER_CERT}"
        "${JARZEM_OTA_CA_BUNDLE}"
)
