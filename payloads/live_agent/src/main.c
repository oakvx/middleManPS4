/* middleManPS4 Live Agent: self-observation transport, not a system tracer.
 * Locally paired LAN only, HMAC-authenticated telemetry with bounded samples.
 * Does not inspect or modify other processes, PSN requests or TLS payloads.
 */
#include "fw_info.h"
#include "live_crypto.h"
#include "live_agent_config.h" /* local private header, excluded from Git */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef MMPS4_PC_IP
#error "Generate live_agent_config.h using python -m host.ps4_sender.live_agent config"
#endif

#define MMPS4_SAMPLES 8U
#define MMPS4_INTERVAL_US 1000000U
#define MMPS4_LINE_BYTES 256U

/* Matches prior self-observer payload ABI. */
int sceKernelUsleep(unsigned int microseconds);

static int send_all(int fd, const char *message)
{
    size_t sent = 0, length = strlen(message);
    while (sent < length) {
        ssize_t n = send(fd, message + sent, length - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_line(int fd, char line[MMPS4_LINE_BYTES])
{
    size_t length = 0;
    while (length < MMPS4_LINE_BYTES - 1U) {
        char ch;
        ssize_t received = recv(fd, &ch, 1, 0);
        if (received != 1) return -1;
        if (ch == '\n') { line[length] = '\0'; return 0; }
        if (ch == '\r' || (unsigned char)ch < 0x20U) return -1;
        line[length++] = ch;
    }
    return -1;
}

static int parse_challenge(const char *line, char nonce[33])
{
    const char prefix[] = "{\"type\":\"challenge\",\"protocol\":1,\"nonce\":\"";
    size_t first = sizeof prefix - 1U, i;
    if (strncmp(line, prefix, first) != 0 || strlen(line) != first + 34U) return -1;
    for (i = 0; i < 32U; i++) {
        char c = line[first + i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
        nonce[i] = c;
    }
    nonce[32] = '\0';
    return strcmp(line + first + 32U, "\"}") == 0 ? 0 : -1;
}

static int send_authenticated(int fd, const unsigned char key[32], const char nonce[33],
                              unsigned int seq, const char *kind, long pid,
                              unsigned int elapsed_ms, int status)
{
    char signed_body[192], frame[MMPS4_LINE_BYTES], mac[65];
    unsigned char digest[32];
    int n = snprintf(signed_body, sizeof signed_body,
                     "mmps4-event-v1|%s|%u|%s|%ld|%u|%d",
                     nonce, seq, kind, pid, elapsed_ms, status);
    if (n <= 0 || (size_t)n >= sizeof signed_body) return -1;
    mmps4_hmac_sha256(key, 32, (const unsigned char *)signed_body, (size_t)n, digest);
    mmps4_hex_encode(digest, 32, mac);
    n = snprintf(frame, sizeof frame,
                 "{\"type\":\"event\",\"protocol\":1,\"seq\":%u,\"kind\":\"%s\","
                 "\"pid\":%ld,\"elapsed_ms\":%u,\"status\":%d,\"mac\":\"%s\"}\n",
                 seq, kind, pid, elapsed_ms, status, mac);
    if (n <= 0 || (size_t)n >= sizeof frame) return -1;
    return send_all(fd, frame);
}

int main(void)
{
    unsigned char key[32], digest[32];
    struct sockaddr_in target;
    struct timeval timeout;
    char line[MMPS4_LINE_BYTES], nonce[33], message[MMPS4_LINE_BYTES];
    char signed_challenge[80], hex_proof[65], fw[96];
    long pid = (long)getpid();
    int fd = -1, result = 1, fw_status;
    unsigned int seq = 0, tick;
    int n;

    if (mmps4_hex_key(MMPS4_PAIR_KEY_HEX, key) != 0 ||
        MMPS4_PC_PORT < 1024 || MMPS4_PC_PORT > 65535) {
        puts("[middleManPS4/live] invalid private configuration");
        return 2;
    }
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons((unsigned short)MMPS4_PC_PORT);
    if (inet_pton(AF_INET, MMPS4_PC_IP, &target.sin_addr) != 1) return 2;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    timeout.tv_sec = 4;
    timeout.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    if (connect(fd, (struct sockaddr *)&target, sizeof target) != 0 ||
        recv_line(fd, line) != 0 || parse_challenge(line, nonce) != 0) goto done;

    n = snprintf(signed_challenge, sizeof signed_challenge, "mmps4-live-v1:%s", nonce);
    if (n <= 0 || (size_t)n >= sizeof signed_challenge) goto done;
    mmps4_hmac_sha256(key, 32, (const unsigned char *)signed_challenge, (size_t)n, digest);
    mmps4_hex_encode(digest, 32, hex_proof);
    n = snprintf(message, sizeof message,
                 "{\"type\":\"auth\",\"protocol\":1,\"proof\":\"%s\"}\n", hex_proof);
    if (n <= 0 || (size_t)n >= sizeof message || send_all(fd, message) != 0 ||
        recv_line(fd, line) != 0 ||
        strcmp(line, "{\"type\":\"accepted\",\"protocol\":1}") != 0) goto done;

    if (send_authenticated(fd, key, nonce, seq++, "agent_start", pid, 0, 0) != 0) goto done;
    fw_status = (int)fw_info_read(fw, sizeof fw);
    /* Firmware value goes only to stdout; telemetry contains status code. */
    if (fw_status == FW_INFO_OK) printf("[middleManPS4/live] firmware=%s\n", fw);
    if (send_authenticated(fd, key, nonce, seq++, "firmware_read", pid, 0, fw_status) != 0)
        goto done;

    for (tick = 1; tick <= MMPS4_SAMPLES; tick++) {
        int sleep_status = sceKernelUsleep(MMPS4_INTERVAL_US);
        if (sleep_status != 0) {
            (void)send_authenticated(fd, key, nonce, seq, "agent_error", pid,
                                     tick * 1000U, sleep_status);
            goto done;
        }
        if (send_authenticated(fd, key, nonce, seq++, "heartbeat", pid, tick * 1000U, 0) != 0)
            goto done;
    }
    if (send_authenticated(fd, key, nonce, seq, "agent_complete", pid,
                           MMPS4_SAMPLES * 1000U, 0) == 0) result = 0;

done:
    memset(key, 0, sizeof key);
    close(fd);
    printf("[middleManPS4/live] session ended status=%d\n", result);
    fflush(stdout);
    return result;
}
