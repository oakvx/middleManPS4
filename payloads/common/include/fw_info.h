#ifndef FW_INFO_H
#define FW_INFO_H

#include <stddef.h>

typedef enum fw_info_status {
    FW_INFO_OK = 0,
    FW_INFO_ERR_UNAVAILABLE = -1,
    FW_INFO_ERR_INVALID_ARGUMENT = -2
} fw_info_status;

fw_info_status fw_info_read(char *buffer, size_t capacity);

#endif
