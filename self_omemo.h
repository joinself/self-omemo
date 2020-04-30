#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct GroupSession GroupSession;

void omemo_add_group_participant(GroupSession *gs, const char *id, OlmSession *s);

GroupSession *omemo_create_group_session(const char *id);

size_t omemo_decrypt(GroupSession *gs,
                     const char *id,
                     uint8_t *pt,
                     size_t pt_len,
                     const uint8_t *ct,
                     size_t ct_len);

size_t omemo_decrypted_size(GroupSession *gs, const uint8_t *ct, size_t ct_len);

void omemo_destroy_group_session(GroupSession *gs);

size_t omemo_encrypt(GroupSession *gs,
                     const uint8_t *pt,
                     size_t pt_len,
                     uint8_t *ct,
                     size_t ct_len);

size_t omemo_encrypted_size(GroupSession *gs, size_t pt_len);
