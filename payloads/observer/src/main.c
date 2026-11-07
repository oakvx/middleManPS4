/*
 * middleManPS4 Observer v0.1 — deliberately limited to self-observation.
 * No process injection, system hooks, TLS interception or credential capture.
 */
#include "fw_info.h"

#include <stdio.h>
#include <unistd.h>

#define OBSERVER_SAMPLES 12U
#define OBSERVER_INTERVAL_US 1000000U

/* Same external userspace-import style as the existing payloads. */
int sceKernelUsleep(unsigned int usec);

int main(void)
{
    char firmware[96];
    unsigned int sample;
    const fw_info_status status = fw_info_read(firmware, sizeof firmware);

    if (status != FW_INFO_OK) {
        printf("[middleManPS4/observer] event=error stage=firmware code=%d\n", (int)status);
        fflush(stdout);
        return 1;
    }

    printf("[middleManPS4/observer] event=start pid=%ld firmware=%s\n",
           (long)getpid(), firmware);
    fflush(stdout);

    for (sample = 1U; sample <= OBSERVER_SAMPLES; ++sample) {
        const int result = sceKernelUsleep(OBSERVER_INTERVAL_US);
        if (result != 0) {
            printf("[middleManPS4/observer] event=error stage=sleep sample=%u code=%d\n",
                   sample, result);
            fflush(stdout);
            return 2;
        }
        printf("[middleManPS4/observer] event=heartbeat sample=%u\n", sample);
        fflush(stdout);
    }

    printf("[middleManPS4/observer] event=complete samples=%u\n", OBSERVER_SAMPLES);
    fflush(stdout);
    return 0;
}
