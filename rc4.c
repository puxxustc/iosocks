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
#if defined(__GNUC__) && 1
#if defined(__amd64__) || defined(__x86_64__)
#define RC4_ASM 1
	__asm__ __volatile__ (
		".1:\n\t"
		"cmpq %[stream], %[end]\n\t"
		"je .2\n\t"
		/* i = (i + 1) & 255; */
		"incl %[i]\n\t"
		"movzbl %b[i], %[i]\n\t"
		/* j = (j + s[i] ) & 255 */
		"movzbl (%[s], %q[i]), %%ecx\n\t"
		"addb %%cl, %b[j]\n\t"
		/* SWAP(s[i], s[j]); */
		"movzbl (%[s], %q[j]), %%edx\n\t"
		"movb %%dl, (%[s], %q[i])\n\t"
		"movb %%cl, (%[s], %q[j])\n\t"
		/* *((uint8_t *)stream) ^= s[(s[i] + s[j]) & 255]; */
		"addl %%edx, %%ecx\n\t"
		"movzbl %%cl, %%ecx\n\t"
		"movb (%[s], %%rcx), %%cl\n\t"
		"xorb %%cl, (%[stream])\n\t"
		/* stream++ */
		"incq %[stream]\n\t"
		"cmpq %[stream], %[end]\n\t"
		"jne .1\n\t"
		".2:\n\t"
		: [i] "=a"(evp->i),
		  [j] "=b"(evp->j)
		: [stream] "r"(stream),
		  [end] "r"(stream+ len),
		  [s] "r"(evp->s),
		  "[i]"(evp->i),
		  "[j]"(evp->j)
		: "memory", "rcx", "rdx"
	);
#elif defined(__i386__)
#define RC4_ASM 1
	__asm__ __volatile__ (
		".1:\n\t"
		"cmpl %[stream], %[end]\n\t"
		"je .2\n\t"
		/* i = (i + 1) & 255; */
		"incl %[i]\n\t"
		"movzbl %b[i], %[i]\n\t"
		/* j = (j + s[i] ) & 255 */
		"movzbl (%[s], %[i]), %%ecx\n\t"
		"addb %%cl, %b[j]\n\t"
		/* SWAP(s[i], s[j]); */
		"movzbl (%[s], %[j]), %%edx\n\t"
		"movb %%dl, (%[s], %[i])\n\t"
		"movb %%cl, (%[s], %[j])\n\t"
		/* *((uint8_t *)stream) ^= s[(s[i] + s[j]) & 255]; */
		"addl %%edx, %%ecx\n\t"
		"movzbl %%cl, %%ecx\n\t"
		"movb (%[s], %%ecx), %%cl\n\t"
		"xorb %%cl, (%[stream])\n\t"
		/* stream++ */
		"incl %[stream]\n\t"
		"cmpl %[stream], %[end]\n\t"
		"jne .1\n\t"
		".2:\n\t"
		: [i] "=a"(evp->i),
		  [j] "=b"(evp->j)
		: [stream] "r"(stream),
		  [end] "r"(stream+ len),
		  [s] "r"(evp->s),
		  "[i]"(evp->i),
		  "[j]"(evp->j)
		: "memory", "ecx", "edx"
	);
#elif defined(__arm__)
#define RC4_ASM 1
	__asm__ __volatile__ (
		".1:\n\t"
		"cmp %[stream], %[end]\n\t"
		"bcs .2\n\t"
		/* i = (i + 1) & 255; */
		"add %[i], %[i], #1\n\t"
		"and %[i], %[i], #255\n\t"
		/* j = (j + s[i] ) & 255 */
		"ldrb r4, [%[s], %[i]]\n\t"
		"add %[j], %[j], r4\n\t"
		"and %[j], %[j], #255\n\t"
		/* SWAP(s[i], s[j]); */
		"ldrb r5, [%[s], %[j]]\n\t"
		"strb r4, [%[s], %[j]]\n\t"
		"strb r5, [%[s], %[i]]\n\t"
		/* *((uint8_t *)stream) ^= s[(s[i] + s[j]) & 255]; */
		"ldrb r6, [%[stream]]\n\t"
		"add r4, r4, r5\n\t"
		"and r4, r4, #255\n\t"
		"ldrb r7, [%[s], r4]\n\t"
		"eor r6, r6, r7\n\t"
		"strb r6, [%[stream]], #1\n\t"
		"cmp %[stream], %[end]\n\t"
		"bne .1\n\t"
		".2:\n\t"
		: [i] "=r"(evp->i),
		  [j] "=r"(evp->j)
		: [stream] "r"(stream),
		  [end] "r"(stream+ len),
		  [s] "r"(evp->s),
		  "[i]"(evp->i),
		  "[j]"(evp->j)
		: "memory", "r4", "r5", "r6", "r7"
	);
#endif
#endif

#ifndef RC4_ASM
	register int i = evp->i;
	register int j = evp->j;
	register uint8_t *s = evp->s;
	register uint8_t *end = (uint8_t *)stream + len;
	for (; (uint8_t *)stream < end; stream++)
	{
		i = (i + 1) & 255;
		j = (j + s[i]) & 255;
		SWAP(s[i], s[j]);
		*((uint8_t *)stream) ^= s[(s[i] + s[j]) & 255];
	}
	evp->i = i;
	evp->j = j;
#endif
}
