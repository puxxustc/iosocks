/*
 * encrypt.h - encryption and decryption
 *
 * Copyright (C) 2014 - 2015, Xiaoxiao <i@xiaoxiao.im>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "rc4.h"

typedef enum
{
	enc_rc4 = 0
} enc_method_t;

typedef struct
{
	enc_method_t method;
	union
	{
		rc4_evp_t rc4;
	} enc_evp, dec_evp;
} enc_evp_t;

extern void enc_init(enc_evp_t *evp, enc_method_t method, const void *key, size_t key_len);
extern void io_encrypt(void *stream, size_t len, enc_evp_t *evp);
extern void io_decrypt(void *stream, size_t len, enc_evp_t *evp);


#endif // ENCRYPT_H
