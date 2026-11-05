#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct notify_request {
    char reserved[45];
    char message[3075];
} notify_request_t;

static int called = 0;
static int notification_result = 0;
int sceKernelSendNotificationRequest(int a, notify_request_t *request, size_t size, int b) {
    assert(a == 0 && b == 0 && size == 3120);
    assert(memcmp(request->reserved, "\0\0\0\0", 4) == 0);
    assert(strcmp(request->message, "PS4 Firmware Lab: hello_world executed") == 0);
    called++;
    return notification_result;
}
int payload_main(void);
int main(void) {
    assert(payload_main() == 0);
    assert(called == 1);
    notification_result = -1;
    assert(payload_main() == 1);
    assert(called == 2);
    puts("C hello_world mock tests: OK");
    return 0;
}
