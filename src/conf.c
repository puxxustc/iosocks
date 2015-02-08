/*
 * conf.c - parse config file
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "conf.h"
#include "log.h"

#define MAX_LINE 1024

static void help(const char *s)
{
	printf("usage: %s\n"
	       "  -h, --help        show this help\n"
	       "  -c <config_file>  config file\n",
	       s);
}

static void _strncpy(char *dest, const char *src, size_t n)
{
	char *end = dest + n;
	while ((dest < end) && ((*dest = *src) != '\0'))
	{
		dest++;
		src++;
	}
	*(end - 1) = '\0';
}

static int read_conf(const char *file, conf_t *conf)
{
	bzero(conf, sizeof(conf_t));

	FILE *f = fopen(file, "rb");
	if (f == NULL)
	{
		LOG("failed to read conf file");
		return -1;
	}

	int line_num = 0;
	char buf[MAX_LINE];
	enum
	{
		null = 0,
		global,
		server,
		local,
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
			if (strcmp(line, "[global]") == 0)
			{
				section = global;
			}
			else if (strcmp(line, "[server]") == 0)
			{
				conf->server_num++;
				section = server;
			}
			else if (strcmp(line, "[local]") == 0)
			{
				section = local;
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
			if (section == global)
			{
				if (strcmp(name, "user") == 0)
				{
					_strncpy(conf->user, value, sizeof(conf->user));
				}
				else if (strcmp(name, "group") == 0)
				{
					_strncpy(conf->group, value, sizeof(conf->group));
				}
			}
			else if (section == server)
			{
				if (conf->server_num > MAX_SERVER)
				{
					continue;
				}
				if (strcmp(name, "address") == 0)
				{
					_strncpy(conf->server[conf->server_num - 1].address, value,
					        sizeof(conf->server[conf->server_num - 1].address));
				}
				else if (strcmp(name, "port") == 0)
				{
					_strncpy(conf->server[conf->server_num - 1].port, value,
					        sizeof(conf->server[conf->server_num - 1].port));
				}
				else if (strcmp(name, "key") == 0)
				{
					_strncpy(conf->server[conf->server_num - 1].key, value,
					        sizeof(conf->server[conf->server_num - 1].key));
				}
			}
			else if (section == local)
			{
				if (strcmp(name, "address") == 0)
				{
					_strncpy(conf->local.address, value,
					        sizeof(conf->local.address));
				}
				else if (strcmp(name, "port") == 0)
				{
					_strncpy(conf->local.port, value, sizeof(conf->local.port));
				}
			}
			else if (section == redir)
			{
				if (strcmp(name, "address") == 0)
				{
					_strncpy(conf->redir.address, value,
					        sizeof(conf->redir.address));
				}
				else if (strcmp(name, "port") == 0)
				{
					_strncpy(conf->redir.port, value, sizeof(conf->redir.port));
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

	if (conf->user[0] == '\0')
	{
		_strncpy(conf->user, "nobody", sizeof(conf->user));
	}
	if (conf->server_num == 0)
	{
		LOG("no server specified");
		return -1;
	}
	for (int i = 0; i < conf->server_num; i++)
	{
		if (conf->server[i].address[0] == '\0')
		{
			_strncpy(conf->server[i].address, "0.0.0.0",
			         sizeof(conf->server[i].address));
		}
		if (conf->server[i].port[0] == '\0')
		{
			_strncpy(conf->server[i].port, "1205",
			         sizeof(conf->server[i].port));
		}
		else
		{
			char *p1 = strchr(conf->server[i].port, ',');
			if (p1 != NULL)
			{
				*p1 = '\0';
			}
			while (p1 != NULL)
			{
				char *p2 = strchr(p1 + 1, ',');
				if (p2 != NULL)
				{
					*p2 = '\0';
				}
				if (conf->server_num < MAX_SERVER)
				{
					_strncpy(conf->server[conf->server_num].address,
					        conf->server[i].address,
					        sizeof(conf->server[conf->server_num].address));
					_strncpy(conf->server[conf->server_num].port, p1 + 1,
					        sizeof(conf->server[conf->server_num].port));
					_strncpy(conf->server[conf->server_num].key,
					        conf->server[i].key,
					        sizeof(conf->server[conf->server_num].key));
					conf->server_num++;
				}
				p1 = p2;
			}
		}
	}
	if (conf->local.address[0] == '\0')
	{
		strcpy(conf->local.address, "127.0.0.1");
	}
	if (conf->local.port[0] == '\0')
	{
		strcpy(conf->local.port, "1080");
	}
	if (conf->redir.address[0] == '\0')
	{
		strcpy(conf->redir.address, "127.0.0.1");
	}
	if (conf->redir.port[0] == '\0')
	{
		strcpy(conf->redir.port, "1081");
	}

	return 0;
}

int parse_args(int argc, char **argv, conf_t *conf)
{
	const char *conf_file = NULL;

	bzero(conf, sizeof(conf_t));

	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
		{
			help(argv[0]);
			return 0;
		}
		else if (strcmp(argv[i], "-c") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			conf_file = argv[i + 1];
			i++;
		}
		else
		{
			fprintf(stderr, "Invalid option: %s\n", argv[i]);
			return 1;
		}
	}
	if (conf_file == NULL)
	{
		help(argv[0]);
		return -1;
	}
	if (read_conf(conf_file, conf) != 0)
	{
		return -1;
	}
	for (int i = 0; i < conf->server_num; i++)
	{
		if (conf->server[i].key[0] == '\0')
		{
			help(argv[0]);
			return -1;
		}
	}

	return 0;
}
