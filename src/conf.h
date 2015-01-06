/*
 * conf.h - parse config file
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

#ifndef CONF_H
#define CONF_H

#define MAX_SERVER 16

typedef struct {
	int server_num;
	struct
	{
		char *address;
		char *port;
		char *key;
	} server[MAX_SERVER];
	struct
	{
		char *address;
		char *port;
	} local;
	struct
	{
		char *address;
		char *port;
		char *upstream_addr;
		char *upstream_port;
	} dns;
} conf_t;

extern int read_conf(const char *file, conf_t *conf);

#endif // CONF_H
