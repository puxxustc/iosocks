/*
 * rc4.c - rc4 stream encryption
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

#include <stdint.h>
#include "rc4.h"

#define SWAP(x, y) do {register uint8_t tmp = (x); (x) = (y); (y) = tmp; } while (0)

void rc4_init(rc4_evp_t *evp, const void *key, size_t key_len)
{
	register int i, j;
	register uint8_t *s = evp->s;
	for (i = 0; i < 256; i++)
	{
		s[i] = (uint8_t)i;
	}
	for (i = 0, j = 0; i < 256; i++)
	{
		j = (j + s[i] + ((uint8_t *)key)[i % key_len]) & 255;
		SWAP(s[i], s[j]);
	}
	evp->i = 0;
	evp->j = 0;
}

void rc4_enc(void *stream, size_t len, rc4_evp_t *evp)
{
	register int i = evp->i;
	register int j = evp->j;
	register uint8_t *s = evp->s;
	for (size_t k = 0; k < len; k++)
	{
		i = (i + 1) & 255;
		j = (j + s[i]) & 255;
		SWAP(s[i], s[j]);
		((uint8_t *)stream)[k] ^= s[(s[i] + s[j]) & 255];
	}
	evp->i = i;
	evp->j = j;
}
