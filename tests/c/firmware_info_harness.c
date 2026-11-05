/* Host-only ABI mock. Tests fw_info and firmware_info/main.c control flow. */
#include "fw_info.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct ps4_sw_version {
    size_t size;
    char version_string[28];
    uint32_t version_value;
    uint64_t reserved_tail;
} ps4_sw_version_t;

static int service_fails = 0;
static int no_version = 0;
static int notifications = 0;

int sceKernelGetSystemSwVersion(ps4_sw_version_t *version) {
    assert(version != NULL);
    assert(version->size == 0x28);
    assert(sizeof(*version) == 0x30);
    if (service_fails) return -1;
    if (!no_version) {
        memcpy(version->version_string, "  12.52  ", 9);
        version->version_value = 0x1252;
    }
    return 0;
}

typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int a, notify_request_t *request, size_t size, int b) {
    assert(a == 0 && b == 0);
    assert(size == 3120);
    assert(request != NULL);
    assert(memcmp(request->reserved, "\0\0\0\0", 4) == 0);
    assert(strstr(request->message, "12.52") != NULL);
    notifications++;
    return 0;
}

int firmware_payload_main(void);

int main(void) {
    char out[96] = {0};
    assert(fw_info_read(NULL, sizeof out) == FW_INFO_ERR_INVALID_ARGUMENT);
    assert(fw_info_read(out, 0) == FW_INFO_ERR_INVALID_ARGUMENT);
    service_fails = 1;
    assert(fw_info_read(out, sizeof out) == FW_INFO_ERR_UNAVAILABLE);
    service_fails = 0;
    no_version = 1;
    assert(fw_info_read(out, sizeof out) == FW_INFO_ERR_UNAVAILABLE);
    no_version = 0;
    assert(fw_info_read(out, 3) == FW_INFO_ERR_INVALID_ARGUMENT);
    assert(out[0] == '\0');
    assert(fw_info_read(out, sizeof out) == FW_INFO_OK);
    assert(strcmp(out, "12.52 (raw 0x00001252)") == 0);
    assert(firmware_payload_main() == 0);
    assert(notifications == 1);
    puts("C firmware_info mock tests: OK");
    return 0;
}
