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

	bzero(conf, sizeof(conf_t));

	int line_num = 0;
	char buf[MAX_LINE];
	enum
	{
		null = 0,
		servers,
		local,
		dns,
		redir
	} section = null;

	while (!feof(f))
	{
		char *line = fgets(buf, MAX_LINE, f);
		if (line == NULL)
		{
			break;
		}
		line_num++;
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
		// 跳过注释和空白行
		if ((*line == ';') || (*line == '#') ||(*line == '\0'))
		{
			continue;
		}
		if (*line == '[')
		{
			// 新的 section
			if (strcmp(line, "[server]") == 0)
			{
				conf->server_num++;
				section = servers;
			}
			else if (strcmp(line, "[local]") == 0)
			{
				section = local;
			}
			else if (strcmp(line, "[dns]") == 0)
			{
				section = dns;
			}
			else if (strcmp(line, "[redir]") == 0)
			{
				section = redir;
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
			if (section == servers)
			{
				if (conf->server_num > MAX_SERVER)
				{
					continue;
				}
				if (strcmp(name, "address") == 0)
				{
					if (conf->server[conf->server_num - 1].address != NULL)
					{
						free(conf->server[conf->server_num - 1].address);
					}
					conf->server[conf->server_num - 1].address = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->server[conf->server_num - 1].port != NULL)
					{
						free(conf->server[conf->server_num - 1].port);
					}
					conf->server[conf->server_num - 1].port = strdup(value);
				}
				else if (strcmp(name, "key") == 0)
				{
					if (conf->server[conf->server_num - 1].key != NULL)
					{
						free(conf->server[conf->server_num - 1].key);
					}
					conf->server[conf->server_num - 1].key = strdup(value);
				}
			}
			else if (section == local)
			{
				if (strcmp(name, "address") == 0)
				{
					if (conf->local.address != NULL)
					{
						free(conf->local.address);
					}
					conf->local.address = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->local.port != NULL)
					{
						free(conf->local.port);
					}
					conf->local.port = strdup(value);
				}
			}
			else if (section == dns)
			{
				if (strcmp(name, "address") == 0)
				{
					if (conf->dns.address != NULL)
					{
						free(conf->dns.address);
					}
					conf->dns.address = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->dns.port != NULL)
					{
						free(conf->dns.port);
					}
					conf->dns.port = strdup(value);
				}
				else if (strcmp(name, "upstream_addr") == 0)
				{
					if (conf->dns.upstream_addr != NULL)
					{
						free(conf->dns.upstream_addr);
					}
					conf->dns.upstream_addr = strdup(value);
				}
				else if (strcmp(name, "upstream_port") == 0)
				{
					if (conf->dns.upstream_port != NULL)
					{
						free(conf->dns.upstream_port);
					}
					conf->dns.upstream_port = strdup(value);
				}
			}
			else if (section == redir)
			{
				if (strcmp(name, "address") == 0)
				{
					if (conf->redir.address != NULL)
					{
						free(conf->redir.address);
					}
					conf->redir.address = strdup(value);
				}
				else if (strcmp(name, "port") == 0)
				{
					if (conf->redir.port != NULL)
					{
						free(conf->redir.port);
					}
					conf->redir.port = strdup(value);
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
