/* Linux host-only mock. The real PS4 ABI/runtime remains unverified. */
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

static int fw_fails;
static int sleep_fails_at;
static int sleeps;

int sceKernelGetSystemSwVersion(ps4_sw_version_t *version)
{
    assert(version != NULL && version->size == 0x28);
    if (fw_fails) return -1;
    memcpy(version->version_string, "12.520.001", 11);
    version->version_value = 0x12520001;
    return 0;
}

int sceKernelUsleep(unsigned int microseconds)
{
    assert(microseconds == 1000000U);
    ++sleeps;
    return sleeps == sleep_fails_at ? -1 : 0;
}

int observer_payload_main(void);

int main(void)
{
    fw_fails = 1;
    assert(observer_payload_main() == 1);
    assert(sleeps == 0);

    fw_fails = 0;
    sleep_fails_at = 3;
    assert(observer_payload_main() == 2);
    assert(sleeps == 3);

    sleeps = 0;
    sleep_fails_at = 0;
    assert(observer_payload_main() == 0);
    assert(sleeps == 12);
    puts("observer mock tests: OK");
    return 0;
}
