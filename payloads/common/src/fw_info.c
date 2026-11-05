#include "fw_info.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * sceKernelGetSystemSwVersion userland structure.
 * OpenOrbis documents a 0x28-byte API structure:
 *   size_t Size; char VersionString[0x1c]; uint32_t Version;
 * Other community implementations include an additional trailing 8-byte
 * reserved field. Allocate 0x30 bytes defensively, while advertising the
 * OpenOrbis 0x28 API length in the Size field. We do not inspect the tail.
 * No firmware offsets or kernel memory access are involved.
 */
typedef struct ps4_sw_version {
    size_t size;
    char version_string[28];
    uint32_t version_value;
    uint64_t reserved_tail;
} ps4_sw_version_t;

_Static_assert(offsetof(ps4_sw_version_t, version_value) == 0x24,
               "PS4 firmware version ABI offset must be 0x24");
_Static_assert(sizeof(ps4_sw_version_t) == 0x30,
               "PS4 firmware version buffer must include trailing guard space");

int sceKernelGetSystemSwVersion(ps4_sw_version_t *version);

fw_info_status fw_info_read(char *buffer, size_t capacity)
{
    ps4_sw_version_t version;
    char *start;
    size_t len;
    int written;

    if (buffer == NULL || capacity == 0U) {
        return FW_INFO_ERR_INVALID_ARGUMENT;
    }
    buffer[0] = '\0';

    memset(&version, 0, sizeof(version));
    version.size = 0x28; /* OpenOrbis ABI: payload length, not backing capacity */

    if (sceKernelGetSystemSwVersion(&version) != 0) {
        return FW_INFO_ERR_UNAVAILABLE;
    }

    version.version_string[sizeof(version.version_string) - 1U] = '\0';

    /* Remove optional padding without inventing a firmware string. */
    start = version.version_string;
    while (*start == ' ') {
        ++start;
    }
    len = strlen(start);
    while (len > 0U && start[len - 1U] == ' ') {
        start[--len] = '\0';
    }
    if (len == 0U) {
        return FW_INFO_ERR_UNAVAILABLE;
    }

    written = snprintf(buffer, capacity, "%s (raw 0x%08X)",
                       start, (unsigned int)version.version_value);
    if (written < 0 || (size_t)written >= capacity) {
        buffer[0] = '\0';
        return FW_INFO_ERR_INVALID_ARGUMENT;
    }
    return FW_INFO_OK;
}
