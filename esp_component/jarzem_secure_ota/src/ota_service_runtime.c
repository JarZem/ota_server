/*
 * Compatibility translation unit for the portable OTA component.
 *
 * ota_service.c now reads the HTTPS port directly from the authenticated
 * provisioning context, so no build-time port override or wrapper function
 * is needed here.
 */
#include "ota_service.c"
