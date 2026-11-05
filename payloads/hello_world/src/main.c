
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/*
 * Notification request used by PS4.
 * Compatible with the ps4-payload-dev SDK sample.
 */
typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(
    int,
    notify_request_t *,
    size_t,
    int
);

int main(void) {
    notify_request_t req;

    memset(&req, 0, sizeof(req));

    snprintf(
        req.message,
        sizeof(req.message),
        "PS4 Firmware Lab: hello_world executed"
    );

    printf(
        "[ps4-firmware-lab] hello_world started\n"
    );

    int rc = sceKernelSendNotificationRequest(
        0,
        &req,
        sizeof(req),
        0
    );

    printf(
        "[ps4-firmware-lab] notification result: %d\n",
        rc
    );

    return rc == 0 ? 0 : 1;
}
