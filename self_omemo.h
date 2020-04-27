#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

struct GroupSession;

extern "C" {

void omemo_add_group_participant(GroupSession *gs, const char *id, OlmSession *s);

GroupSession *omemo_create_group_session();

void omemo_destroy_group_session(GroupSession *gs);

} // extern "C"
