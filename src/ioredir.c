/*
 * ioredir.c - A transparent TCP proxy
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
#include <time.h>
#include <unistd.h>
#include "conf.h"
#include "encrypt.h"
#include "log.h"
#include "sha512.h"
#include "utils.h"

#define UNUSED(x) do {(void)(x);} while (0)

// 缓冲区大小
#define BUF_SIZE 8192

// 最大连接尝试次数
#define MAX_TRY 4

// 魔数
#define MAGIC 0x526f6e61

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

// 连接控制块结构
typedef struct
{
	ev_io w_local_read;
	ev_io w_local_write;
	ev_io w_remote_read;
	ev_io w_remote_write;
	ssize_t rx_bytes;
	ssize_t tx_bytes;
	ssize_t rx_offset;
	ssize_t tx_offset;
	int sock_local;
	int sock_remote;
	int server_id;
	int server_tried;
	char dst_addr[257];
	char dst_port[15];
	enc_evp_t enc_evp;
	uint8_t rx_buf[BUF_SIZE];
	uint8_t tx_buf[BUF_SIZE];
} ctx_t;

static void timer_cb(EV_P_ ev_timer *w, int revents);
static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void iosocks_send_cb(EV_P_ ev_io *w, int revents);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static int  select_server(void);
static void connect_server(EV_P_ ctx_t *ctx);
static void cleanup(EV_P_ ctx_t *ctx);

// 配置信息
static conf_t conf;

// 服务器的信息
static struct
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char *key;
	size_t key_len;
	time_t health;		// 0 可用，非 0 不可用
} servers[MAX_SERVER];

int main(int argc, char **argv)
{
	if (parse_args(argc, argv, &conf) != 0)
	{
		return EXIT_FAILURE;
	}

	// Daemonize
	if (conf.daemon)
	{
		if (daemonize(conf.pidfile, conf.logfile) != 0)
		{
			return -1;
		}
	}

	// 服务器信息
	struct addrinfo hints;
	struct addrinfo *res;
	for (int i = 0; i < conf.server_num; i++)
	{
		servers[i].health = 0;
		servers[i].key = conf.server[i].key;
		servers[i].key_len = strlen(servers[i].key);
		bzero(&hints, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo(conf.server[i].address, conf.server[i].port, &hints, &res) != 0)
		{
			LOG("failed to resolv %s:%s", conf.server[i].address, conf.server[i].port);
			return 2;
		}
		memcpy(&servers[i].addr, res->ai_addr, res->ai_addrlen);
		servers[i].addrlen = res->ai_addrlen;
		freeaddrinfo(res);
	}

	// 初始化本地监听 socket
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(conf.redir.address, conf.redir.port, &hints, &res) != 0)
	{
		LOG("wrong local_host/local_port");
		return EXIT_FAILURE;
	}
	int sock_listen = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_listen < 0)
	{
		ERROR("socket");
		return EXIT_FAILURE;
	}
	setnonblock(sock_listen);
	setreuseaddr(sock_listen);
	if (bind(sock_listen, (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
	{
		ERROR("bind");
		return EXIT_FAILURE;
	}
	freeaddrinfo(res);
	if (listen(sock_listen, 1024) != 0)
	{
		ERROR("listen");
		return EXIT_FAILURE;
	}

	// 初始化 ev
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal w_sigint;
	ev_signal w_sigterm;
	ev_signal_init(&w_sigint, signal_cb, SIGINT);
	ev_signal_init(&w_sigterm, signal_cb, SIGTERM);
	ev_signal_start(EV_A_ &w_sigint);
	ev_signal_start(EV_A_ &w_sigterm);
	ev_io w_listen;
	ev_io_init(&w_listen, accept_cb, sock_listen, EV_READ);
	ev_io_start(EV_A_ &w_listen);
	ev_timer w_timer;
	ev_timer_init(&w_timer, timer_cb, 5.0, 5.0);
	ev_timer_start(EV_A_ &w_timer);

	// 切换用户
	if (runas(conf.user) != 0)
	{
		ERROR("runas");
	}

	LOG("starting ioredir at %s:%s", conf.redir.address, conf.redir.port);

	// 执行事件循环
	ev_run(EV_A_ 0);

	// 退出
	close(sock_listen);
	LOG("Exit");

	return EXIT_SUCCESS;
}

static void timer_cb(EV_P_ ev_timer *w, int revents)
{
	UNUSED(loop);
	UNUSED(w);
	UNUSED(revents);

	time_t t = time(NULL);
	for (int i = 0; i < conf.server_num; i++)
	{
		if (servers[i].health + 20 < t)
		{
			servers[i].health = 0;
		}
	}
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
	ctx->sock_local = accept(w->fd, NULL, NULL);
	if (ctx->sock_local < 0)
	{
		ERROR("accept");
		free(ctx);
		return;
	}
	setnonblock(ctx->sock_local);
	settimeout(ctx->sock_local);
	setkeepalive(ctx->sock_local);

	// 获取原始地址
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	if (getdestaddr(ctx->sock_local, (struct sockaddr *)&addr, &addrlen) != 0)
	{
		ERROR("getdestaddr");
		close(ctx->sock_local);
		free(ctx);
		return;
	}
	if (addr.ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &(((struct sockaddr_in *)&addr)->sin_addr), ctx->dst_addr, INET_ADDRSTRLEN);
		sprintf(ctx->dst_port, "%u", ntohs(((struct sockaddr_in *)&addr)->sin_port));
	}
	else
	{
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&addr)->sin6_addr), ctx->dst_addr, INET6_ADDRSTRLEN);
		sprintf(ctx->dst_port, "%u", ntohs(((struct sockaddr_in6 *)&addr)->sin6_port));
	}

	// 连接 iosocks server
	ctx->server_tried = 0;
	connect_server(EV_A_ ctx);
}

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ev_io_stop(EV_A_ w);

	if (geterror(w->fd) == 0)
	{
		// 连接成功
		ev_io_init(&ctx->w_remote_write, iosocks_send_cb, ctx->sock_remote, EV_WRITE);
		ev_io_start(EV_A_ &ctx->w_remote_write);
	}
	else
	{
		// 连接失败
		servers[ctx->server_id].health = time(NULL);
		if (ctx->server_tried < MAX_TRY)
		{
			LOG("connect to ioserver failed, try again");
			close(ctx->sock_remote);
			connect_server(EV_A_ ctx);
		}
		else
		{
			LOG("connect to ioserver failed, abort");
			close(ctx->sock_local);
			close(ctx->sock_remote);
			free(ctx);
		}
	}
}

static void iosocks_send_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ev_io_stop(EV_A_ w);

	ssize_t n = send(ctx->sock_remote, ctx->tx_buf, ctx->tx_bytes, MSG_NOSIGNAL);
	if (n != ctx->tx_bytes)
	{
		if (n < 0)
		{
			ERROR("send");
		}
		close(ctx->sock_local);
		close(ctx->sock_remote);
		free(ctx);
		return;
	}

	ev_io_init(&ctx->w_local_read, local_read_cb, ctx->sock_local, EV_READ);
	ev_io_init(&ctx->w_local_write, local_write_cb, ctx->sock_local, EV_WRITE);
	ev_io_init(&ctx->w_remote_read, remote_read_cb, ctx->sock_remote, EV_READ);
	ev_io_init(&ctx->w_remote_write, remote_write_cb, ctx->sock_remote, EV_WRITE);
	ctx->w_local_read.data = (void *)ctx;
	ctx->w_local_write.data = (void *)ctx;
	ctx->w_remote_read.data = (void *)ctx;
	ev_io_start(EV_A_ &ctx->w_local_read);
	ev_io_start(EV_A_ &ctx->w_remote_read);
}

static void local_read_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ctx->tx_bytes = recv(ctx->sock_local, ctx->tx_buf, BUF_SIZE, 0);
	if (ctx->tx_bytes <= 0)
	{
		if (ctx->tx_bytes < 0)
		{
			LOG("client reset");
		}
		cleanup(EV_A_ ctx);
		return;
	}
	io_encrypt(ctx->tx_buf, ctx->tx_bytes, &ctx->enc_evp);
	ssize_t n = send(ctx->sock_remote, ctx->tx_buf, ctx->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			ctx->tx_offset = 0;
		}
		else
		{
			ERROR("send");
			cleanup(EV_A_ ctx);
			return;
		}
	}
	else if (n < ctx->tx_bytes)
	{
		ctx->tx_offset = n;
		ctx->tx_bytes -= n;
	}
	else
	{
		return;
	}
	ev_io_start(EV_A_ &ctx->w_remote_write);
	ev_io_stop(EV_A_ w);
}

static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)w->data;

	UNUSED(revents);
	assert(ctx != NULL);
	assert(ctx->rx_bytes > 0);

	ssize_t n = send(ctx->sock_local, ctx->rx_buf + ctx->rx_offset, ctx->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return;
		}
		else
		{
			ERROR("send");
			cleanup(EV_A_ ctx);
			return;
		}
	}
	else if (n < ctx->rx_bytes)
	{
		ctx->rx_offset += n;
		ctx->rx_bytes -= n;
	}
	else
	{
		ev_io_start(EV_A_ &ctx->w_remote_read);
		ev_io_stop(EV_A_ w);
	}
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ctx->rx_bytes = recv(ctx->sock_remote, ctx->rx_buf, BUF_SIZE, 0);
	if (ctx->rx_bytes <= 0)
	{
		if (ctx->rx_bytes < 0)
		{
			LOG("server reset");
		}
		cleanup(EV_A_ ctx);
		return;
	}
	io_decrypt(ctx->rx_buf, ctx->rx_bytes, &ctx->enc_evp);
	ssize_t n = send(ctx->sock_local, ctx->rx_buf, ctx->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			ctx->rx_offset = 0;
		}
		else
		{
			ERROR("send");
			cleanup(EV_A_ ctx);
			return;
		}
	}
	else if (n < ctx->rx_bytes)
	{
		ctx->rx_offset = n;
		ctx->rx_bytes -= n;
	}
	else
	{
		return;
	}
	ev_io_start(EV_A_ &ctx->w_local_write);
	ev_io_stop(EV_A_ w);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);
	assert(ctx->tx_bytes > 0);

	ssize_t n = send(ctx->sock_remote, ctx->tx_buf + ctx->tx_offset, ctx->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return;
		}
		else
		{
			ERROR("send");
			cleanup(EV_A_ ctx);
			return;
		}
	}
	else if (n < ctx->tx_bytes)
	{
		ctx->tx_offset += n;
		ctx->tx_bytes -= n;
	}
	else
	{
		ev_io_start(EV_A_ &ctx->w_local_read);
		ev_io_stop(EV_A_ w);
	}
}

static int select_server(void)
{
	unsigned char rand_num;
	int id;
	int tries = 0;
	while (tries++ < 100)
	{
		rand_bytes(&rand_num, sizeof(unsigned char));
		id = (int)rand_num % conf.server_num;
		if (servers[id].health == 0)
		{
			return id;
		}
	}
	return -1;
}

static void connect_server(EV_P_ ctx_t *ctx)
{
	// 随机选择一个 server
	ctx->server_id = select_server();
	if (ctx->server_id < 0)
	{
		LOG("no available server, abort");
		close(ctx->sock_local);
		free(ctx);
		return;
	}
	ctx->server_tried++;
	LOG("connect %s:%s via %s:%s",
	    ctx->dst_addr, ctx->dst_port,
	    conf.server[ctx->server_id].address,
	    conf.server[ctx->server_id].port);

	// IoSocks Request
	// +-------+------+------+------+
	// | MAGIC | HOST | PORT |  IV  |
	// +-------+------+------+------+
	// |   4   | 257  |  15  | 236  |
	// +-------+------+------+------+
	uint8_t key[64];
	rand_bytes(ctx->rx_buf, 236);
	memcpy(ctx->rx_buf + 236, servers[ctx->server_id].key, servers[ctx->server_id].key_len);
	sha512(key, ctx->rx_buf, 236 + servers[ctx->server_id].key_len);
	bzero(ctx->tx_buf, 276);
	*((uint32_t *)(ctx->tx_buf)) = htonl(MAGIC);
	strcpy((char *)ctx->tx_buf + 4, ctx->dst_addr);
	strcpy((char *)ctx->tx_buf + 261, ctx->dst_port);
	memcpy(ctx->tx_buf + 276, ctx->rx_buf, 236);
	enc_init(&ctx->enc_evp, enc_rc4, key, 64);
	io_encrypt(ctx->tx_buf, 276, &ctx->enc_evp);
	ctx->tx_bytes = 512;

	// 建立远程连接
	ctx->sock_remote = socket(servers[ctx->server_id].addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (ctx->sock_remote < 0)
	{
		ERROR("socket");
		close(ctx->sock_local);
		free(ctx);
		return;
	}
	setnonblock(ctx->sock_remote);
	settimeout(ctx->sock_remote);
	setkeepalive(ctx->sock_remote);
	if (connect(ctx->sock_remote,
	        (struct sockaddr *)&servers[ctx->server_id].addr,
	        servers[ctx->server_id].addrlen) != 0)
	{
		if (errno != EINPROGRESS)
		{
			// 连接失败
			servers[ctx->server_id].health = time(NULL);
			if (ctx->server_tried < MAX_TRY)
			{
				LOG("connect to ioserver failed, try again");
				close(ctx->sock_remote);
				connect_server(EV_A_ ctx);
			}
			else
			{
				LOG("connect to ioserver failed, abort");
				close(ctx->sock_local);
				close(ctx->sock_remote);
				free(ctx);
			}
			return;
		}
	}
	ev_io_init(&ctx->w_remote_write, connect_cb, ctx->sock_remote, EV_WRITE);
	ctx->w_remote_write.data = (void *)ctx;
	ev_io_start(EV_A_ &ctx->w_remote_write);
}

static void cleanup(EV_P_ ctx_t *ctx)
{
	ev_io_stop(EV_A_ &ctx->w_local_read);
	ev_io_stop(EV_A_ &ctx->w_local_write);
	ev_io_stop(EV_A_ &ctx->w_remote_read);
	ev_io_stop(EV_A_ &ctx->w_remote_write);
	close(ctx->sock_local);
	close(ctx->sock_remote);
	free(ctx);
}
