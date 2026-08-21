# JarZem Secure OTA bootstrap. Include this before ESP-IDF project.cmake.
get_filename_component(JARZEM_OTA_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(JARZEM_OTA_PROJECT_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

if(DEFINED PYTHON AND EXISTS "${PYTHON}")
    set(JARZEM_OTA_PYTHON "${PYTHON}")
else()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(JARZEM_OTA_PYTHON "${Python3_EXECUTABLE}")
endif()

execute_process(
    COMMAND "${JARZEM_OTA_PYTHON}"
            "${JARZEM_OTA_REPO_ROOT}/tools/esp_ota/prebuild_validate.py"
            --project "${JARZEM_OTA_PROJECT_ROOT}"
            --submodule "${JARZEM_OTA_REPO_ROOT}"
    RESULT_VARIABLE JARZEM_OTA_VALIDATE_RESULT
    COMMAND_ECHO STDOUT
)
if(NOT JARZEM_OTA_VALIDATE_RESULT EQUAL 0)
    message(FATAL_ERROR "JarZem Secure OTA pre-build validation failed")
endif()

list(APPEND EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}")
