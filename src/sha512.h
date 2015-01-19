/*
 * sha512.h - SHA-512 (RFC 4634)
 *
 * Copyed from libsodium[1], with some modification.
 *
 * [1]: https://github.com/jedisct1/libsodium
 */

#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
extern void sha512(void *digest, const void *in, size_t len);

#endif // SHA512_H
