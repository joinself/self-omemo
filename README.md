# self-omemo

self-olm is a library that delivers omemo group messaging ontop of matrix's olm.

## Requirements

In order to build this library, you must have:

- [rust](https://rust-lang.org)
- [clang](https://releases.llvm.org/download.html)
- [olm](https://github.com/aldgate-ventures/olm)
- [libsodium](https://github.com/jedisct1/libsodium)

## Building

Once you have all of the requirements set up, you can run:

```sh
cargo build
```

If you are building a release, you should run:

```sh
cargo build --release
```

This will produce a shared library specific to your platform, as well as generate headers for the library.

## Installing

You will need to copy the two generated artifacts to an install path, as follows:

```sh
sudo cp self_omemo.h /usr/local/include/

sudo cp build/release/libself_omemo.so /usr/local/lib/
# or
sudo cp build/debug/libself_omemo.so /usr/local/lib/
```

## Usage

self-olm is an additional layer ontop of olm. This means that all session and account management needs to be handled by the caller of the library.

### group session

A group session stores all participants and their olm sessions. Every time you need to encrypt or decrypt a message from a recipient, you will need to provide the group session object, containing all of the participants.

You can create a group session like:

```C
#include <stdio.h>
#include <string.h>
#include <self_olm.h>
#include <self_omemo.h>

int main () {
    // create a group session
    char my_identity[] = "myID:myDevice";

    gs = omemo_create_group_session(my_identity);

    // setup the olm sessions from an incoming message or create a new outbound session.
    // if there are existing sessions, you should load them from persistent storage.
    ...

    // add some participants to the group session
    char prt1[] = "alice:1";
    char prt2[] = "bob:1";

    omemo_add_group_participant(gs, prt1, prt1_session);
    omemo_add_group_participant(gs, prt2, prt2_session);

    // encrypt or decrypt some messages with the group session
    ...

    // free the memory of the group session once its no longer needed
    omemo_destroy_group_session(gs);

    return 0;
}
```


### encrypting

Once you have all participants and their olm sessions added to the group session, you can encrypt like:

```C
#include <stdio.h>
#include <string.h>
#include <self_olm.h>
#include <self_omemo.h>

int main () {
    // create a group session and add participants
    ...

    size_t plaintext_size = 12;
    const unsigned char plaintext[] = "my plaintext";    

    // get the size of the ciphertext
    size_t ciphertext_size = omemo_encrypted_size(gs, plaintext_size);

    // allocate memory for the ciphertext
    ciphertext = (unsigned char*) malloc(ciphertext_size * sizeof(unsigned char));

    // encrypt the message.
    // this will return the size of the encrypted message if successful
    // or this will return 0 if unsucessful
    success = omemo_encrypt(gs, plaintext, plaintext_size, ciphertext, cipertext_size);
    if (success == 0) {
        return 1;
    }

    // free the memory of the group session once its no longer needed
    ...

    return 0;
}
```

### decrypting

Once you have all participants and their olm sessions added to the group session, you can decrypt like:

```C
#include <stdio.h>
#include <string.h>
#include <self_olm.h>
#include <self_omemo.h>

int main () {
    // create a group session and add participants
    ...

    size_t ciphertext_size = 22;
    const unsigned char ciphertext[] = "received group message";

    // the sender of the message
    char sender[] = "alice:1";

    // get the size of the plaintext
    size_t plaintext_size = omemo_decrypted_size(gs, cipertext, ciphertext_size);

    // allocate memory for the plaintext
    plaintext = (unsigned char*) malloc(plaintext_size * sizeof(unsigned char));

    // encrypt the message.
    // this will return the size of the encrypted message if successful
    // or this will return 0 if unsucessful
    success = omemo_decrypt(gs, sender, plaintext, plaintext_size, ciphertext, cipertext_size);
    if (success == 0) {
        return 1;
    }

    // free the memory of the group session once its no longer needed
    ...

    return 0;
}
```


### C strings

Note: rust takes ownership of the memory that gets passed to it for any c string.
      this means that the caller does not need to free this memory. This is only
      the case for the id's of participants, as well as the string thats passed
      in when creatin the group session. If this causes issues, this can easily
      be changed.
