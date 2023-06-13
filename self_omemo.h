#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct GroupSession GroupSession;

struct GroupSession *omemo_create_group_session(void);

void omemo_set_identity(struct GroupSession *gs, const char *id);

void omemo_destroy_group_session(struct GroupSession *gs);

void omemo_add_group_participant(struct GroupSession *gs, const char *id, OlmSession *s);

size_t omemo_encrypted_size(struct GroupSession *gs, size_t pt_len);

size_t omemo_decrypted_size(struct GroupSession *gs, const uint8_t *ct, size_t ct_len);

size_t omemo_encrypt(struct GroupSession *gs,
                     const uint8_t *pt,
                     size_t pt_len,
                     uint8_t *ct,
                     size_t ct_len);

size_t omemo_decrypt(struct GroupSession *gs,
                     const char *id,
                     uint8_t *pt,
                     size_t pt_len,
                     const uint8_t *ct,
                     size_t ct_len);
