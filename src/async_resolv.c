/*
 * async_resolv.c - async resolv
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

#include <assert.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include "async_resolv.h"
#include "log.h"

#define UNUSED(x) do {(void)(x);} while (0)

// 最大域名解析次数
#define MAX_TRY 3

typedef struct
{
	struct gaicb req;
	struct addrinfo hints;
	struct addrinfo *res;
	void (*cb)(struct addrinfo *, void *);
	void *data;
	int tried;
	char host[257];
	char port[15];
} ctx_t;

static void resolv_cb(int signo, siginfo_t *info, void *context);

int resolv_init(void)
{
	// SIGIO 信号
	struct sigaction sa;
	sa.sa_handler = (void(*) (int))resolv_cb;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGIO, &sa, NULL) != 0)
	{
		LOG("failed to setup SIGIO handler");
		return -1;
	}
	else
	{
		return 0;
	}
}

void async_resolv(const char *host, const char *port,
                         void (*cb)(struct addrinfo *, void *),
                         void *data)
{
	ctx_t *ctx = (ctx_t *)malloc(sizeof(ctx_t));

	ctx->hints.ai_family = AF_UNSPEC;
	ctx->hints.ai_socktype = SOCK_STREAM;
	strcpy(ctx->host, host);
	strcpy(ctx->port, port);
	ctx->req.ar_name = ctx->host;
	ctx->req.ar_service = ctx->port;
	ctx->req.ar_request = &(ctx->hints);
	ctx->req.ar_result = NULL;
	ctx->cb = cb;
	ctx->data = data;
	ctx->tried = 0;

	struct gaicb *req_ptr = &(ctx->req);
	struct sigevent sevp;
	sevp.sigev_notify = SIGEV_SIGNAL;
	sevp.sigev_signo = SIGIO;
	sevp.sigev_value.sival_ptr = (void *)ctx;
	if (getaddrinfo_a(GAI_NOWAIT, &req_ptr, 1, &sevp) != 0)
	{
		ERROR("getaddrinfo_a");
		(ctx->cb)(NULL, ctx->data);
		free(ctx);
		return;
	}
	ctx->tried++;
}

static void resolv_cb(int signo, siginfo_t *info, void *context)
{
	ctx_t *ctx = (ctx_t *)info->si_value.sival_ptr;

	UNUSED(context);
	assert(signo == SIGIO);
	assert(ctx != NULL);

	if (gai_error(&(ctx->req)) == 0)
	{
		// 域名解析成功
		(ctx->cb)(ctx->req.ar_result, ctx->data);
		free(ctx);
	}
	else
	{
		// 域名解析失败
		if (ctx->tried < MAX_TRY)
		{
			LOG("failed to resolv host: %s, try again", ctx->host);
			struct gaicb *req_ptr = &(ctx->req);
			struct sigevent sevp;
			sevp.sigev_notify = SIGEV_SIGNAL;
			sevp.sigev_signo = SIGIO;
			sevp.sigev_value.sival_ptr = (void *)ctx;
			if (getaddrinfo_a(GAI_NOWAIT, &req_ptr, 1, &sevp) != 0)
			{
				ERROR("getaddrinfo_a");
				(ctx->cb)(NULL, ctx->data);
				free(ctx);
				return;
			}
			ctx->tried++;
		}
		else
		{
			LOG("failed to resolv host: %s, abort", ctx->host);
			(ctx->cb)(NULL, ctx->data);
			free(ctx);
		}
	}
}
