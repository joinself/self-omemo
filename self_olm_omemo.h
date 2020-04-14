#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct GroupSession GroupSession;

typedef struct {
  uint8_t _private[0];
} Session;

size_t add_participant(GroupSession *self, int8_t *id, Session *participant);

size_t create_group_session(void);

size_t encrypted_size(GroupSession *self, size_t ptlen);

GroupSession *new(void);
