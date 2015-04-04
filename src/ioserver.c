/*
 * ioserver.c - iosocks server
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
#include <assert.h>
#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "async_connect.h"
#include "async_resolv.h"
#include "conf.h"
#include "crypto.h"
#include "log.h"
#include "md5.h"
#include "relay.h"
#include "utils.h"

#define UNUSED(x) do {(void)(x);} while (0)

// 连接控制块
typedef struct
{
	int sock;
	int server_id;
	struct addrinfo *_res;
	struct addrinfo *res;
	ev_io w_read;
	crypto_evp_t evp;
} ctx_t;

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void iosocks_recv_cb(EV_P_ ev_io *w, int revents);
static void resolv_cb(struct addrinfo *res, void *data);
static void connect_cb(int sock, void *data);

// 服务器的信息
static struct
{
	char *key;
} servers[MAX_SERVER];

struct ev_loop *loop;

int main(int argc, char **argv)
{
	conf_t conf;

	if (parse_args(argc, argv, &conf) != 0)
	{
		return EXIT_FAILURE;
	}

	// daemonize
	if (conf.daemon)
	{
		if (daemonize(conf.pidfile, conf.logfile) != 0)
		{
			return EXIT_FAILURE;
		}
	}

	// 服务器信息
	for (int i = 0; i < conf.server_num; i++)
	{
		servers[i].key = conf.server[i].key;
	}

	// 初始化 ev_signal
	loop = EV_DEFAULT;
	ev_signal w_sigint;
	ev_signal w_sigterm;
	ev_signal_init(&w_sigint, signal_cb, SIGINT);
	ev_signal_init(&w_sigterm, signal_cb, SIGTERM);
	ev_signal_start(EV_A_ &w_sigint);
	ev_signal_start(EV_A_ &w_sigterm);

	// 初始化本地监听 socket
	int sock_listen[conf.server_num];
	ev_io w_listen[conf.server_num];
	struct addrinfo hints;
	struct addrinfo *res;
	for (int i = 0; i < conf.server_num; i++)
	{
		bzero(&hints, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(conf.server[i].address, conf.server[i].port, &hints, &res) != 0)
		{
			LOG("failed to resolv %s:%s", conf.server[i].address, conf.server[i].port);
			return EXIT_FAILURE;
		}
		sock_listen[i] = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock_listen[i] < 0)
		{
			ERROR("socket");
			return EXIT_FAILURE;
		}
		setnonblock(sock_listen[i]);
		setreuseaddr(sock_listen[i]);
		if (bind(sock_listen[i], (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
		{
			ERROR("bind");
			return EXIT_FAILURE;
		}
		freeaddrinfo(res);
		if (listen(sock_listen[i], 1024) != 0)
		{
			ERROR("listen");
			return EXIT_FAILURE;
		}
		ev_io_init(&(w_listen[i]), accept_cb, sock_listen[i], EV_READ);
		w_listen[i].data = (void *)(uintptr_t)i;
		ev_io_start(EV_A_ &(w_listen[i]));
		LOG("starting ioserver at %s:%s", conf.server[i].address, conf.server[i].port);
	}

	// 初始化 async_resolv
	if (resolv_init() != 0)
	{
		return EXIT_FAILURE;
	}

	// drop root privilege
	if (runas(conf.user) != 0)
	{
		ERROR("runas");
	}

	// 执行事件循环
	ev_run(EV_A_ 0);

	// 退出
	for (int i = 0; i < conf.server_num; i++)
	{
		close(sock_listen[i]);
	}
	LOG("Exit");

	return EXIT_SUCCESS;
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
	UNUSED(revents);
	assert((w->signum == SIGINT) || (w->signum == SIGTERM));
	ev_break(EV_A_ EVBREAK_ALL);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	UNUSED(revents);

	ctx_t *ctx = (ctx_t *)malloc(sizeof(ctx_t));
	if (ctx == NULL)
	{
		LOG("out of memory");
		return;
	}
	ctx->sock = accept(w->fd, NULL, NULL);
	if (ctx->sock < 0)
	{
		ERROR("accept");
		free(ctx);
		return;
	}
	setnonblock(ctx->sock);
	settimeout(ctx->sock);
	setkeepalive(ctx->sock);
	ctx->server_id = (int)(uintptr_t)(w->data);
	ev_io_init(&ctx->w_read, iosocks_recv_cb, ctx->sock, EV_READ);
	ctx->w_read.data = (void *)ctx;
	ev_io_start(EV_A_ &ctx->w_read);
}

static void iosocks_recv_cb(EV_P_ ev_io *w, int revents)
{
	assert(w->data != NULL);
	UNUSED(revents);

	ctx_t *ctx = (ctx_t *)(w->data);

	ev_io_stop(EV_A_ w);

	uint8_t buf[288];
	ssize_t n = recv(ctx->sock, buf, sizeof(buf), 0);
	if (n != 288)
	{
		if (n < 0)
		{
			ERROR("recv");
		}
		else
		{
			LOG("bad client");
		}
		close(ctx->sock);
		free(ctx);
		return;
	}

	// IoSocks Request
	// +------+------+------+
	// |  IV  | HOST | PORT |
	// +------+------+------+
	// |  16  | 257  |  15  |
	// +------+------+------+
	crypto_init(&(ctx->evp), servers[ctx->server_id].key, buf);
	crypto_decrypt(buf + 16, 257 + 15, &(ctx->evp));
	uint8_t tmp[16];
	md5(tmp, buf + 16, 257 + 15);
	if (memcmp(buf, tmp, 16) != 0)
	{
		LOG("illegal client");
		close(ctx->sock);
		free(ctx);
		return;
	}
	char *host = (char *)(buf + 16);
	char *port = (char *)(buf + 16 + 257);
	host[256] = '\0';
	port[14] = '\0';
	LOG("connect %s:%s", host, port);
	async_resolv(host, port, resolv_cb, ctx);
}

static void resolv_cb(struct addrinfo *res, void *data)
{
	assert(data != NULL);

	ctx_t *ctx = (ctx_t *)data;

	if (res != NULL)
	{
		// 域名解析成功，建立远程连接
		ctx->_res = res;
		ctx->res = res;
		async_connect(ctx->res->ai_addr, ctx->res->ai_addrlen, connect_cb, data);
	}
	else
	{
		// 域名解析失败
		close(ctx->sock);
		free(ctx);
	}
}

static void connect_cb(int sock, void *data)
{
	ctx_t *ctx = (ctx_t *)(data);

	assert(ctx != NULL);

	if (sock > 0)
	{
		// 连接成功
		freeaddrinfo(ctx->_res);
		relay(sock, ctx->sock, &(ctx->evp));
		free(ctx);
	}
	else
	{
		// 连接失败
		close(ctx->sock);
		ctx->res = ctx->res->ai_next;
		if (ctx->res != NULL)
		{
			// 尝试连接下一个地址
			async_connect(ctx->res->ai_addr, ctx->res->ai_addrlen, connect_cb, data);
		}
		else
		{
			// 所有地址均连接失败
			LOG("connect failed");
			close(ctx->sock);
			freeaddrinfo(ctx->_res);
			free(ctx);
		}
	}
}
