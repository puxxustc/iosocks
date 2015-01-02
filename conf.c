/*
 * conf.c - parse config file
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "conf.h"
#include "log.h"

#define MAX_LINE 1024

int read_conf(const char *file, conf_t *conf)
{
	FILE *f = fopen(file, "rb");
	if (f == NULL)
	{
		LOG("failed to read conf file");
		return -1;
	}

	conf->server_addr = NULL;
	conf->server_port = NULL;
	conf->key = NULL;
	conf->local_addr = NULL;
	conf->local_port = NULL;

	int line_num = 0;
	char buf[MAX_LINE];
	enum
	{
		null = 0,
		server,
		local
	} section = null;

	while (!feof(f))
	{
		fgets(buf, MAX_LINE, f);
		line_num++;
		char *line = buf;
		// 跳过行首空白符
		while (isspace(*line))
		{
			line++;
		}
		// 去除行尾的空白符
		char *end = line + strlen(line) - 1;
		while ((end >= line) && (isspace(*end)))
		{
			*end = '\0';
			end--;
		}
		// 跳过注释和空行
		if ((*line == ';') || (*line == '#'))
		{
			continue;
		}
		if (*line == '[')
		{
			// 新的 section
			if (strcmp(line, "[server]") == 0)
			{
				section = server;
			}
			else if (strcmp(line, "[local]") == 0)
			{
				section = local;
			}
			else
			{
				LOG("parse conf file failed at line: %d", line_num);
				fclose(f);
				return -1;
			}
		}
		else
		{
			char *p = strchr(line, '=');
			if (p == NULL)
			{
				LOG("parse conf file failed at line: %d", line_num);
				fclose(f);
				return -1;
			}
			*p = '\0';
			char *name = line;
			char *value = p + 1;
			if (section == server)
			{
				if (strcmp(name, "address") == 0)
				{
					if (conf->server_addr != NULL)
					{
						free(conf->server_addr);
					}
					conf->server_addr = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->server_port != NULL)
					{
						free(conf->server_port);
					}
					conf->server_port = strdup(value);
				}
				else if (strcmp(name, "key") == 0)
				{
					if (conf->key != NULL)
					{
						free(conf->key);
					}
					conf->key = strdup(value);
				}
			}
			else if (section == local)
			{
				if (strcmp(name, "address") == 0)
				{
					if (conf->local_addr != NULL)
					{
						free(conf->local_addr);
					}
					conf->local_addr = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->local_port != NULL)
					{
						free(conf->local_port);
					}
					conf->local_port = strdup(value);
				}
			}
			else
			{
				LOG("parse conf file failed at line: %d", line_num);
				fclose(f);
				return -1;
			}
		}
	}
	fclose(f);
	return 0;
}
