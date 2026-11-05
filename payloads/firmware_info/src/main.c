#include "fw_info.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Notification ABI as used by the ps4-payload-dev hello_world sample. */
typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

int main(void)
{
    notify_request_t notification;
    char version[96];
    fw_info_status status = fw_info_read(version, sizeof(version));

    memset(&notification, 0, sizeof(notification));

    if (status == FW_INFO_OK) {
        snprintf(notification.message, sizeof(notification.message),
                 "fwSpoofer | System software: %s", version);
        printf("[fwSpoofer] %s\n", notification.message);
    } else {
        snprintf(notification.message, sizeof(notification.message),
                 "fwSpoofer | Firmware read failed (error %d)",
                 (int)status);
        printf("[fwSpoofer] firmware read failed: %d\n", (int)status);
    }

    /* Show a notification even if the read failed, for remote debugging. */
    int notify_result = sceKernelSendNotificationRequest(
        0, &notification, sizeof(notification), 0);
    printf("[fwSpoofer] notification result: %d\n", notify_result);

    return (status == FW_INFO_OK && notify_result == 0) ? 0 : 1;
}
