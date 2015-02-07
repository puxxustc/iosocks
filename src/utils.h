/*
 * utils.h - Some util functions
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

#ifndef UTILS_H
#define UTILS_H

#include <sys/socket.h>

extern int setnonblock(int fd);
extern int settimeout(int fd);
extern int setreuseaddr(int fd);
extern int setkeepalive(int fd);
extern int getdestaddr(int fd, struct sockaddr *addr, socklen_t *addrlen);
extern int geterror(int fd);
extern int setuser(const char *user, const char *group);
extern ssize_t rand_bytes(void *stream, size_t len);

#endif // UTILS_H
