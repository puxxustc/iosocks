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
#include "md5.h"

#define MAX_LINE 1024

static void help(const char *s)
{
	printf("usage: %s\n"
	       "  -h, --help            show this help\n"
	       "  -c, --config <file>   config file\n"
	       "  -d, --daemon          daemonize after initialization\n"
	       "  -p, --pidfile <file>  PID file\n"
	       "  --logfile <file>      log file\n",
	       s);
}

#define my_strcpy(dest, src) _strncpy(dest, src, sizeof(dest))
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
	FILE *f = fopen(file, "rb");
	if (f == NULL)
	{
		fprintf(stderr, "failed to read conf file\n");
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
				fprintf(stderr, "line %d: wrong section\n", line_num);
				fclose(f);
				return -1;
			}
		}
		else
		{
			char *p = strchr(line, '=');
			if (p == NULL)
			{
				fprintf(stderr, "line %d: no \'=\\ found\n", line_num);
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
					my_strcpy(conf->user, value);
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
					my_strcpy(conf->server[conf->server_num - 1].address, value);
				}
				else if (strcmp(name, "port") == 0)
				{
					my_strcpy(conf->server[conf->server_num - 1].port, value);
				}
				else if (strcmp(name, "key") == 0)
				{
					md5(conf->server[conf->server_num - 1].key, value, strlen(value));
				}
			}
			else if (section == local)
			{
				if (strcmp(name, "address") == 0)
				{
					my_strcpy(conf->local.address, value);
				}
				else if (strcmp(name, "port") == 0)
				{
					my_strcpy(conf->local.port, value);
				}
			}
			else if (section == redir)
			{
				if (strcmp(name, "address") == 0)
				{
					my_strcpy(conf->redir.address, value);
				}
				else if (strcmp(name, "port") == 0)
				{
					my_strcpy(conf->redir.port, value);
				}
			}
			else
			{
				fprintf(stderr, "line %d: no section set\n", line_num);
				fclose(f);
				return -1;
			}
		}
	}
	fclose(f);

	if (conf->user[0] == '\0')
	{
		strcpy(conf->user, "nobody");
	}
	if (conf->server_num == 0)
	{
		fprintf(stderr, "no server set in config file\n");
		return -1;
	}
	for (int i = 0; i < conf->server_num; i++)
	{
		if (conf->server[i].address[0] == '\0')
		{
			strcpy(conf->server[i].address, "0.0.0.0");
		}
		if (conf->server[i].port[0] == '\0')
		{
			strcpy(conf->server[i].port, "1205");
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
					my_strcpy(conf->server[conf->server_num].address,
					          conf->server[i].address);
					my_strcpy(conf->server[conf->server_num].port, p1 + 1);
					my_strcpy(conf->server[conf->server_num].key,
					          conf->server[i].key);
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
		if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
		{
			help(argv[0]);
			return -1;
		}
		else if ((strcmp(argv[i], "-c") == 0) || (strcmp(argv[i], "--config") == 0))
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "missing filename after '%s'\n", argv[i]);
				return 1;
			}
			conf_file = argv[i + 1];
			i++;
		}
		else if ((strcmp(argv[i], "-d") == 0) || (strcmp(argv[i], "--daemon") == 0))
		{
			conf->daemon = 1;
		}
		else if ((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--pidfile") == 0))
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "missing filename after '%s'\n", argv[i]);
				return 1;
			}
			my_strcpy(conf->pidfile, argv[i + 1]);
			i++;
		}
		else if (strcmp(argv[i], "--logfile") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "missing filename after '%s'\n", argv[i]);
				return 1;
			}
			my_strcpy(conf->logfile, argv[i + 1]);
			i++;
		}
		else
		{
			fprintf(stderr, "invalid option: %s\n", argv[i]);
			return 1;
		}
	}
	if (conf_file == NULL)
	{
		help(argv[0]);
		return -1;
	}
	if (conf->daemon)
	{
		if (conf->pidfile[0] == '\0')
		{
			fprintf(stderr, "no pidfile specified\n");
			return -1;
		}
		if (conf->logfile[0] == '\0')
		{
			fprintf(stderr, "no logfile specified\n");
			return -1;
		}
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
