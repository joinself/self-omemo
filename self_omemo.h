#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define self_base64_VARIANT_URLSAFE sodium_base64_VARIANT_URLSAFE

#define self_base64_VARIANT_URLSAFE_NO_PADDING sodium_base64_VARIANT_URLSAFE_NO_PADDING

#define self_base64_VARIANT_ORIGINAL sodium_base64_VARIANT_ORIGINAL

#define self_base64_VARIANT_ORIGINAL_NO_PADDING sodium_base64_VARIANT_ORIGINAL_NO_PADDING

#define self_crypto_aead_xchacha20poly1305_ietf_ABYTES crypto_aead_xchacha20poly1305_ietf_ABYTES

#define self_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

#define self_crypto_aead_xchacha20poly1305_ietf_KEYBYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES

typedef struct GroupSession GroupSession;

typedef struct OlmAccount OlmAccount;

typedef struct OlmSession OlmSession;

struct GroupSession *self_omemo_create_group_session(void);

void self_omemo_set_identity(struct GroupSession *gs, const char *id);

void self_omemo_destroy_group_session(struct GroupSession *gs);

void self_omemo_add_group_participant(struct GroupSession *gs,
                                      const char *id,
                                      struct OlmSession *s);

size_t self_omemo_encrypted_size(struct GroupSession *gs, size_t pt_len);

size_t self_omemo_decrypted_size(struct GroupSession *gs, const uint8_t *ct, size_t ct_len);

size_t self_omemo_encrypt(struct GroupSession *gs,
                          const uint8_t *pt,
                          size_t pt_len,
                          uint8_t *ct,
                          size_t ct_len);

size_t self_omemo_decrypt(struct GroupSession *gs,
                          const char *id,
                          uint8_t *pt,
                          size_t pt_len,
                          const uint8_t *ct,
                          size_t ct_len);

struct OlmAccount *self_olm_account(void *memory);

uint64_t self_olm_account_size(void);

uint64_t self_olm_create_account_random_length(struct OlmAccount *account);

uint64_t self_olm_create_account(struct OlmAccount *account, void *random, uint64_t random_length);

uint64_t self_olm_import_account(struct OlmAccount *account,
                                 void *ed25519_secret_key,
                                 void *ed25519_public_key,
                                 void *curve25519_secret_key,
                                 void *curve25519_public_key);

uint64_t self_olm_unpickle_account(struct OlmAccount *account,
                                   const void *key,
                                   uint64_t key_length,
                                   void *pickled,
                                   uint64_t pickled_length);

uint64_t self_olm_pickle_account(struct OlmAccount *account,
                                 const void *key,
                                 uint64_t key_length,
                                 void *pickled,
                                 uint64_t pickled_length);

uint64_t self_olm_pickle_account_length(const struct OlmAccount *account);

uint64_t self_olm_account_signature_length(const struct OlmAccount *account);

uint64_t self_olm_account_sign(struct OlmAccount *account,
                               const void *message,
                               uint64_t message_length,
                               void *signature,
                               uint64_t signature_length);

uint64_t self_olm_account_max_number_of_one_time_keys(struct OlmAccount *account);

uint64_t self_olm_account_mark_keys_as_published(struct OlmAccount *account);

uint64_t self_olm_account_generate_one_time_keys_random_length(struct OlmAccount *account,
                                                               uint64_t number_of_keys);

uint64_t self_olm_account_generate_one_time_keys(struct OlmAccount *account,
                                                 uint64_t number_of_keys,
                                                 void *random,
                                                 uint64_t random_length);

uint64_t self_olm_account_one_time_keys_length(const struct OlmAccount *account);

uint64_t self_olm_account_one_time_keys(struct OlmAccount *account,
                                        void *one_time_keys,
                                        uint64_t one_time_keys_length);

uint64_t self_olm_remove_one_time_keys(struct OlmAccount *account, struct OlmSession *session);

uint64_t self_olm_account_identity_keys_length(struct OlmAccount *account);

uint64_t self_olm_account_identity_keys(struct OlmAccount *account,
                                        void *identity_keys,
                                        uint64_t identity_key_length);

const int8_t *self_olm_account_last_error(const struct OlmAccount *account);

void self_olm_account_destroy(struct OlmAccount *account);

struct OlmSession *self_olm_session(void *memory);

uint64_t self_olm_session_size(void);

uint64_t self_olm_create_outbound_session_random_length(const struct OlmSession *session);

uint64_t self_olm_create_outbound_session(struct OlmSession *session,
                                          const struct OlmAccount *account,
                                          const void *their_identity_key,
                                          uint64_t their_identity_key_length,
                                          const void *their_one_time_key,
                                          uint64_t their_one_time_key_length,
                                          void *random,
                                          uint64_t random_length);

uint64_t self_olm_create_inbound_session(struct OlmSession *session,
                                         struct OlmAccount *account,
                                         void *one_time_key_message,
                                         uint64_t message_length);

uint64_t self_olm_create_inbound_session_from(struct OlmSession *session,
                                              struct OlmAccount *account,
                                              const void *their_identity_key,
                                              uint64_t their_identity_key_length,
                                              void *one_time_key_message,
                                              uint64_t message_length);

uint64_t self_olm_unpickle_session(struct OlmSession *session,
                                   const void *key,
                                   uint64_t key_length,
                                   void *pickled,
                                   uint64_t pickled_length);

uint64_t self_olm_pickle_session(struct OlmSession *session,
                                 const void *key,
                                 uint64_t key_length,
                                 void *pickled,
                                 uint64_t pickled_length);

uint64_t self_olm_pickle_session_length(const struct OlmSession *session);

uint64_t self_olm_encrypt_message_type(const struct OlmSession *session);

uint64_t self_olm_matches_inbound_session(struct OlmSession *session,
                                          void *one_time_key_message,
                                          uint64_t message_length);

uint64_t self_olm_matches_inbound_session_from(struct OlmSession *session,
                                               const void *their_identity_key,
                                               uint64_t their_identity_key_length,
                                               void *one_time_key_message,
                                               uint64_t message_length);

const int8_t *self_olm_session_last_error(struct OlmSession *session);

void self_olm_session_destroy(struct OlmSession *session);

int32_t self_base642bin(uint8_t *bin,
                        uint64_t bin_maxlen,
                        const int8_t *b64,
                        uint64_t b64_len,
                        const int8_t *ignore,
                        uint64_t *bin_len,
                        const int8_t **b64_end,
                        int32_t variant);

int8_t *self_bin2base64(int8_t *b64,
                        uint64_t b64_maxlen,
                        const uint8_t *bin,
                        uint64_t bin_len,
                        int32_t variant);

uint64_t self_base64_ENCODED_LEN(uint64_t bin_len, int32_t variant);

void self_crypto_aead_xchacha20poly1305_ietf_keygen(uint8_t *k);

int32_t self_crypto_aead_xchacha20poly1305_ietf_encrypt(uint8_t *c,
                                                        uint64_t *clen_p,
                                                        const uint8_t *m,
                                                        uint64_t mlen,
                                                        const uint8_t *ad,
                                                        uint64_t adlen,
                                                        const uint8_t *nsec,
                                                        const uint8_t *npub,
                                                        const uint8_t *k);

int32_t self_crypto_aead_xchacha20poly1305_ietf_decrypt(uint8_t *m,
                                                        uint64_t *mlen_p,
                                                        uint8_t *nsec,
                                                        const uint8_t *c,
                                                        uint64_t clen,
                                                        const uint8_t *ad,
                                                        uint64_t adlen,
                                                        const uint8_t *npub,
                                                        const uint8_t *k);

int32_t self_crypto_sign_ed25519_pk_to_curve25519(uint8_t *curve25519_pk,
                                                  const uint8_t *ed25519_pk);

int32_t self_crypto_sign_ed25519_sk_to_curve25519(uint8_t *curve25519_sk,
                                                  const uint8_t *ed25519_sk);

uint64_t self_crypto_sign_publickeybytes(void);

void self_randombytes_buf(void *buf, uint64_t size);
