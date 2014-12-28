/*
 * log.c - log system
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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include "log.h"

void __log(FILE *stream, const char *format, ...)
{
	static double start_time = -1.0;
	double now;
	struct timeval t;
	gettimeofday(&t, NULL);
	now = t.tv_sec + t.tv_usec / 1000000.0;
	if (start_time < 0.0)
	{
		start_time = now;
	}
	fprintf(stream, "[%8.2lf] ", now - start_time);

	va_list args;
	va_start(args, format);
	vfprintf(stream, format, args);
	va_end(args);
	putchar('\n');
}

void __err(const char *msg)
{
	__log(stderr, "%s: %s", msg, strerror(errno));
}

