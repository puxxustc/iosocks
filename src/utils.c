/*
 * utils.c - Some util functions
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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "utils.h"

#ifndef IP6T_SO_ORIGINAL_DST
#  define IP6T_SO_ORIGINAL_DST 80
#endif

ssize_t rand_bytes(void *stream, size_t len)
{
	static int urand = -1;
	if (urand == -1)
	{
		urand = open("/dev/urandom", O_RDONLY, 0);
	}
	if (urand < 0)
	{
		return -1;
	}
	return read(urand, stream, len);
}

int setnonblock(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
	{
		return -1;
	}
	if (-1 == fcntl(fd, F_SETFL, flags | O_NONBLOCK))
	{
		return -1;
	}
	return 0;
}

int settimeout(int fd)
{
	struct timeval timeout = { .tv_sec = 10, .tv_usec = 0};
	if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return -1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return -1;
	}
	return 0;
}

int setreuseaddr(int fd)
{
	int reuseaddr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) != 0)
	{
		return -1;
	}
	return 0;
}

int setkeepalive(int fd)
{
	int keepalive = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) != 0)
	{
		return -1;
	}
	return 0;
}

int getdestaddr(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	if (getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, addr, addrlen) == 0)
	{
		return 0;
	}
	if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, addr, addrlen) == 0)
	{
		return 0;
	}
	return -1;
}

int getsockerror(int fd)
{
	int error = 0;
	socklen_t len = sizeof(int);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0)
	{
		return -1;
	}
	return error;
}

int runas(const char *user)
{
	struct passwd *pw_ent = NULL;

	if (user != NULL)
	{
		pw_ent = getpwnam(user);
	}

	if (pw_ent != NULL)
	{
		if (setregid(pw_ent->pw_gid, pw_ent->pw_gid) != 0)
		{
			return -1;
		}
		if (setreuid(pw_ent->pw_uid, pw_ent->pw_uid) != 0)
		{
			return -1;
		}
	}

	return 0;
}

int daemonize(const char *pidfile, const char *logfile)
{
	pid_t pid;

	pid = fork();
	if (pid < 0)
	{
		fprintf(stderr, "fork: %s\n", strerror(errno));
		return -1;
	}

	if (pid > 0)
	{
		FILE *fp = fopen(pidfile, "w");
		if (fp == NULL)
		{
			fprintf(stderr, "Invalid pid file\n");
		}
		else
		{
			fprintf(fp, "%d", pid);
			fclose(fp);
		}
		exit(EXIT_SUCCESS);
	}

	umask(0);

	if (setsid() < 0)
	{
		fprintf(stderr, "setsid: %s\n", strerror(errno));
		return -1;
	}

	fclose(stdin);
	FILE *fp;
	fp = freopen(logfile, "w", stdout);
	if (fp == NULL)
	{
		fprintf(stderr, "freopen: %s\n", strerror(errno));
		return -1;
	}
	fp = freopen(logfile, "w", stderr);
	if (fp == NULL)
	{
		fprintf(stderr, "freopen: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}
