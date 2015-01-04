/*
 * encrypt.c - encryption and decryption
 *
 * Copyright (C) 2014, Xiaoxiao <i@xiaoxiao.im>
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

#include <assert.h>
#include "encrypt.h"
#include "rc4.h"

void enc_init(enc_evp_t *evp, enc_method_t method, const void *key, size_t key_len)
{
	evp->method = method;
	switch (method)
	{
	case enc_rc4:
	{
		rc4_init(&evp->enc_evp.rc4, key, key_len);
		rc4_init(&evp->dec_evp.rc4, key, key_len);
		break;
	}
	default:
	{
		// 不应该来到这里
		assert(0 != 0);
		break;
	}
	}
}

void io_encrypt(void *stream, size_t len, enc_evp_t *evp)
{
	switch (evp->method)
	{
	case enc_rc4:
	{
		rc4_enc(stream, len, &evp->enc_evp.rc4);
		break;
	}
	default:
	{
		// 不应该来到这里
		assert(0 != 0);
		break;
	}
	}
}

void io_decrypt(void *stream, size_t len, enc_evp_t *evp)
{
	switch (evp->method)
	{
	case enc_rc4:
	{
		rc4_dec(stream, len, &evp->dec_evp.rc4);
		break;
	}
	default:
	{
		// 不应该来到这里
		assert(0 != 0);
		break;
	}
	}
}
