/*
 * mem.c - memory pool
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

#include <stdlib.h>
#include "mem.h"

// 对齐的字节数
#define ALIGN (sizeof(long))

// 内存池最大个数
#define MEM_POOL_MAX 8

static size_t g_pool_count;
static struct
{
	size_t size;
	size_t count;
	size_t used;
	void **state;
} block[MEM_POOL_MAX];

bool mem_init(size_t *block_size, size_t *block_count, size_t pool_count)
{
	if ((pool_count <= 0) || (pool_count > MEM_POOL_MAX))
	{
		return false;
	}
	// 对 block_size 按升序排序
	for (size_t i = 1; i < pool_count; i++)
	{
		register size_t size = block_size[i];
		register size_t count = block_count[i];
		ssize_t j;
		for (j = (ssize_t)i - 1; (j >= 0) && (block_size[j] > size); j--)
		{
			block_size[j + 1] = block_size[j];
			block_count[j + 1] = block_count[j];
		}
		block_size[j + 1] = size;
		block_count[j + 1] = count;
	}
	g_pool_count = pool_count;
	size_t total = 0;
	for (size_t i = 0; i < pool_count; i++)
	{
		block[i].size = (block_size[i] + ALIGN - 1) & ~(ALIGN - 1);
		block[i].count = block_count[i];
		total += block[i].size * block[i].count;
	}
	void *pool = (void *)malloc(total);
	if (pool == NULL)
	{
		return false;
	}
	void *ptr = pool;
	for (size_t i = 0; i < pool_count; i++)
	{
		block[i].state = (void **)malloc(sizeof(void *) * block_count[i]);
		if (block[i].state == NULL)
		{
			free(pool);
			for (size_t j = 0; j < i; j++)
			{
				free(block[i].state);
			}
			return false;
		}
		for (size_t j = 0; j < block[i].count; j++)
		{
			block[i].state[j] = ptr;
			ptr += block[i].size;
		}
	}
	return true;
}

void *mem_new(size_t size)
{
	if (g_pool_count == 0)
	{
		return NULL;
	}
	// 找一个块足够大，且有空闲块的地址池
	for (size_t i = 0; i < g_pool_count; i++)
	{
		if ((block[i].size >= size) && (block[i].used < block[i].count))
		{
			return block[i].state[block[i].used++];
		}
	}
	return malloc(size);
}

void mem_delete(void *ptr)
{
	if (g_pool_count == 0)
	{
		return;
	}

	for (size_t i = 0; i < g_pool_count; i++)
	{
		for (size_t j = 0; j < block[i].used; j++)
		{
			if (block[i].state[j] == ptr)
			{
				for (size_t k = j; k < block[i].used - 1; k++)
				{
					block[i].state[k] = block[i].state[k + 1];
				}
				block[i].state[--block[i].used] = ptr;
				return;
			}
		}
	}
	free(ptr);
	return;
}
