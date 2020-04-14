#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct GroupMessage GroupMessage;

size_t create_group_session(void);

size_t encode_group_message(GroupMessage group_message, uint8_t *buf);
