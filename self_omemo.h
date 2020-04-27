#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct GroupSession GroupSession;

void omemo_add_group_participant(GroupSession *gs, const char *id, OlmSession *s);

GroupSession *omemo_create_group_session(void);

void omemo_destroy_group_session(GroupSession *gs);
