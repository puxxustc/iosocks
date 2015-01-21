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

#include <assert.h>
#include <stdlib.h>
#include "mem.h"

// 对齐的字节数
#define ALIGN (sizeof(long))

// cluster 最大个数
#define CLUSTER_MAX 8

static struct
{
	void *start;
	void *end;
	size_t cluster_count;
	struct
	{
		size_t chunk_size;
		size_t chunk_count;
		size_t chunk_used;
		void **chunk_ptr;
		void *start;
		void *end;
	} cluster[CLUSTER_MAX];
} mem;

int mem_init(size_t *chunk_size, size_t *chunk_count, size_t cluster_count)
{
	if ((cluster_count <= 0) || (cluster_count > CLUSTER_MAX))
	{
		return -1;
	}
	// 对 chunk_size 按升序排序
	for (size_t i = 1; i < cluster_count; i++)
	{
		size_t size = chunk_size[i];
		size_t count = chunk_count[i];
		ssize_t j;
		for (j = (ssize_t)i - 1; (j >= 0) && (chunk_size[j] > size); j--)
		{
			chunk_size[j + 1] = chunk_size[j];
			chunk_count[j + 1] = chunk_count[j];
		}
		chunk_size[j + 1] = size;
		chunk_count[j + 1] = count;
	}
	mem.cluster_count = cluster_count;
	size_t total = 0;
	for (size_t i = 0; i < cluster_count; i++)
	{
		mem.cluster[i].chunk_size = (chunk_size[i] + ALIGN - 1) & ~(ALIGN - 1);
		mem.cluster[i].chunk_count = chunk_count[i];
		total += mem.cluster[i].chunk_size * mem.cluster[i].chunk_count;
	}
	mem.start = (void *)malloc(total);
	if (mem.start == NULL)
	{
		return -1;
	}
	mem.end = mem.start + total;
	void *p = mem.start;
	for (size_t i = 0; i < cluster_count; i++)
	{
		mem.cluster[i].chunk_ptr = (void **)malloc(sizeof(void *) * chunk_count[i]);
		if (mem.cluster[i].chunk_ptr == NULL)
		{
			free(mem.start);
			for (size_t j = 0; j < i; j++)
			{
				free(mem.cluster[i].chunk_ptr);
			}
			return -1;
		}
		mem.cluster[i].start = p;
		for (size_t j = 0; j < mem.cluster[i].chunk_count; j++)
		{
			mem.cluster[i].chunk_ptr[j] = p;
			p += mem.cluster[i].chunk_size;
		}
		mem.cluster[i].end = p;
	}
	return 0;
}

void mem_destroy(void)
{
	free(mem.start);
	for (size_t i = 0; i < mem.cluster_count; i++)
	{
		free(mem.cluster[i].chunk_ptr);
	}
}

void *mem_new(size_t size)
{
	assert(mem.cluster_count != 0);

	// 找一个 chunk 足够大，且有空闲 chunk 的 cluster
	for (size_t i = 0; i < mem.cluster_count; i++)
	{
		if (   (mem.cluster[i].chunk_size >= size)
		    && (mem.cluster[i].chunk_used < mem.cluster[i].chunk_count))
		{
			return mem.cluster[i].chunk_ptr[mem.cluster[i].chunk_used++];
		}
	}
	return malloc(size);
}

void mem_delete(void *ptr)
{
	assert(mem.cluster_count != 0);

	if ((ptr >= mem.start) && (ptr < mem.end))
	{
		for (size_t i = 0; i < mem.cluster_count; i++)
		{
			if ((ptr >= mem.cluster[i].start) && (ptr < mem.cluster[i].end))
			{
				for (size_t j = 0; j < mem.cluster[i].chunk_used; j++)
				{
					if (mem.cluster[i].chunk_ptr[j] == ptr)
					{
						for (size_t k = j; k < mem.cluster[i].chunk_used - 1; k++)
						{
							mem.cluster[i].chunk_ptr[k] = mem.cluster[i].chunk_ptr[k + 1];
						}
						mem.cluster[i].chunk_ptr[--mem.cluster[i].chunk_used] = ptr;
						return;
					}
				}
				// 不应该来到这里
				assert(0 != 0);
			}
		}
	}
	free(ptr);
}
