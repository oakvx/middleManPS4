/* Host test substitutes PS4 firmware and sleep APIs; it never invokes a console. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct mock_sw_version {
    size_t size;
    char version_string[28];
    uint32_t version_value;
    uint64_t reserved_tail;
} mock_sw_version;
int sceKernelGetSystemSwVersion(mock_sw_version *version)
{
    assert(version && version->size == 0x28);
    memcpy(version->version_string,"12.520.001",11);
    version->version_value = 0x12520001;
    return 0;
}
int sceKernelUsleep(unsigned int microseconds)
{
    assert(microseconds == 1000000U);
    return getenv("MMPS4_TEST_FAIL_SLEEP") != NULL ? -1 : 0;
}
