# self-omemo

self-olm is a library that delivers omemo group messaging ontop of matrix's olm.

## Requirements

In order to build this library, you must have:

- [rust](https://rust-lang.org)
- [clang](https://releases.llvm.org/download.html)
- [olm](https://github.com/joinself/self-olm)
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

If you are building for mobile, you should perform these additional steps

1. install the android sdk and ndk to your home path: https://developer.android.com/ndk
2. add the compile targets via rustup
```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```
3. download github.com/joinself/self-olm

4. follow instructions inside of `self-olm` to build for android. This should mean setting `android/local.properties` to `ndk.dir=/home/tom/android-sdk/ndk-bundle` and running `./gradlew assemble`.

5. grab the compiled artifacts and copy them to `/usr/local/`:
```sh
cp android/olm-sdk/src/main/libs/* /usr/local/lib/
```

6. configure cargo to point to the ndk path. add the following to `~/.cargo/config`:
```sh
[target.aarch64-linux-android]
ar = "/home/tom/android-sdk/ndk-bundle/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar"
linker = "/home/tom/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
[target.armv7-linux-androideabi]
ar = "/home/tom/android-sdk/ndk-bundle/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar"
linker = "/home/tom/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
[target.i686-linux-android]
ar = "/home/tom/android-sdk/ndk-bundle/toolchains/x86-4.9/prebuilt/linux-x86_64/bin/i686-linux-android-ar"
linker = "/home/tom/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android21-clang"
[target.x86_64-linux-android]
ar = "/home/tom/android-sdk/ndk-bundle/toolchains/x86_64-4.9/prebuilt/linux-x86_64/bin/x86_64-linux-android-ar"
linker = "/home/tom/android-sdk/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
```
7. in the project root, build for each target:
```sh
cargo build --release --target aarch64-linux-android && \
cargo build --release --target armv7-linux-androideabi && \
cargo build --release --target x86_64-linux-android && \
cargo build --release --target i686-linux-android
```

Build artifacts will be output in `target/$ARCH/rls/` or `target/$ARCH/debug` if building a debug build.


## Installing

You will need to copy the two generated artifacts to an install path, as follows:

```sh
sudo cp self_omemo.h /usr/local/include/

sudo cp build/release/libself_omemo.so /usr/local/lib/
# or
sudo cp build/debug/libself_omemo.so /usr/local/lib/
```

## Installing a released version

First check the [list of self-omemo releases](https://github.com/joinself/self-omemo/releases) and choose the one you want to install. In the example below we will be installing version `0.11.0`.

##### Debian/Ubuntu
```bash
curl -LO https://github.com/joinself/self-omemo/releases/download/0.11.0/self-omemo_0.11.0_amd64.deb
apt install -y ./self-omemo_0.11.0_amd64.deb
```

##### CentOS/Fedora/RedHat
```bash
yum install -y libstdc++-static
rpm -Uvh https://github.com/joinself/self-omemo/releases/download/0.11.0/self-omemo-0.11.0-1.x86_64.rpm
```

##### MacOS - AMD64
```bash
brew tap joinself/crypto
brew install libself-omemo
```

##### MacOS - ARM64
Brew on M1 macs currently lacks environment variables needed for the SDK to find the `omemo` library, so you will need to add some additional configuration to your system:

In your `~/.zshrc`, add:
```bash
export C_INCLUDE_PATH=/opt/homebrew/include/
export LIBRARY_PATH=$LIBRARY_PATH:/opt/homebrew/lib
```

You should then be able to run:

```bash
source ~/.zshrc
brew tap joinself/crypto
brew install --build-from-source libself-omemo
```

Note, you may also need to create `/usr/local/lib` if it does not exist:
```bash
sudo mkdir /usr/local/lib
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

    gs = omemo_create_group_session();

    omemo_set_identity(gs, my_identity);

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
