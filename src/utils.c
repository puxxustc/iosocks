/*
 * utils.c - Some util functions
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

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <pwd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <unistd.h>
#include "utils.h"

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

int geterror(int fd)
{
	int error = 0;
	socklen_t len = sizeof(int);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0)
	{
		return -1;
	}
	return error;
}

int setuser(const char *user, const char *group)
{
	struct passwd *pw_ent = NULL;
	struct group *gr_ent = NULL;
	uid_t uid = 0;
	gid_t gid = 0;

	if (user != NULL)
	{
		pw_ent = getpwnam(user);
	}
	if (group != NULL)
	{
		gr_ent = getgrnam(group);
	}

	if (pw_ent != NULL)
	{
		uid = pw_ent->pw_uid;
		gid = pw_ent->pw_gid;
	}

	if (gr_ent != NULL)
	{
		gid = gr_ent->gr_gid;
	}

	if (setregid(gid, gid) != 0)
	{
		return -1;
	}
	if (setreuid(uid, uid) != 0)
	{
		return -1;
	}
	return 0;
}

ssize_t rand_bytes(void *stream, size_t len)
{
	static int urand = -1;
	if (urand == -1)
	{
		urand = open("/dev/urandom", O_RDONLY, 0);
	}
	return read(urand, stream, len);
}
