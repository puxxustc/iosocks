/*
 * rc4.h - rc4 stream encryption
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

#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

typedef struct
{
	uint8_t s[256];
	int i;
	int j;
} rc4_evp_t;

extern void rc4_init(rc4_evp_t *evp, const void *key, size_t key_len);
extern void rc4_enc(void *stream, size_t len, rc4_evp_t *evp);
#define rc4_dec rc4_enc

#endif // RC4_H
