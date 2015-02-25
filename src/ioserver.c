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
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "conf.h"
#include "encrypt.h"
#include "log.h"
#include "mem.h"
#include "sha512.h"
#include "utils.h"

#define UNUSED(x) do {(void)(x);} while (0)

// 缓冲区大小
#define BUF_SIZE 8192

// 最大域名解析次数
#define MAX_TRY 4

// 魔数
#define MAGIC 0x526f6e61

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif


// 域名解析控制块
typedef struct
{
	struct gaicb req;
	struct addrinfo hints;
	struct addrinfo *res;
	char host[257];
	char port[15];
} gai_t;

// 连接控制块
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
	int resolv_tried;
	gai_t *gai;
	enc_evp_t enc_evp;
	uint8_t rx_buf[BUF_SIZE];
	uint8_t tx_buf[BUF_SIZE];
} ctx_t;

static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void iosocks_recv_cb(EV_P_ ev_io *w, int revents);
static void emit_resolv(ctx_t *ctx);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static void resolv_cb(int signo, siginfo_t *info, void *context);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void cleanup(EV_P_ ctx_t *ctx);

// 服务器的信息
static struct
{
	char *key;
	size_t key_len;
} servers[MAX_SERVER];

static struct ev_loop *loop;

int main(int argc, char **argv)
{
	conf_t conf;

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
	for (int i = 0; i < conf.server_num; i++)
	{
		servers[i].key = conf.server[i].key;
		servers[i].key_len = strlen(servers[i].key);
	}

	// 初始化内存池
	mem_reg(sizeof(ctx_t), IOSERVER_CONN);
	if (mem_init() != 0)
	{
		LOG("Out of memory");
		return 2;
	}

	// 初始化 ev_signal
	loop = EV_DEFAULT;
	ev_signal w_sigint;
	ev_signal w_sigterm;
	ev_signal_init(&w_sigint, signal_cb, SIGINT);
	ev_signal_init(&w_sigterm, signal_cb, SIGTERM);
	ev_signal_start(EV_A_ &w_sigint);
	ev_signal_start(EV_A_ &w_sigterm);

	// SIGIO 信号
	struct sigaction sa;
	sa.sa_handler = (void(*) (int))resolv_cb;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGIO, &sa, NULL) != 0)
	{
		LOG("failed to setup SIGUSR1 handler");
		return 3;
	}

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
			return 4;
		}
		sock_listen[i] = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock_listen[i] < 0)
		{
			ERROR("socket");
			return 4;
		}
		setnonblock(sock_listen[i]);
		setreuseaddr(sock_listen[i]);
		if (bind(sock_listen[i], (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
		{
			ERROR("bind");
			return 4;
		}
		freeaddrinfo(res);
		if (listen(sock_listen[i], 1024) != 0)
		{
			ERROR("listen");
			return 4;
		}
		ev_io_init(&(w_listen[i]), accept_cb, sock_listen[i], EV_READ);
		w_listen[i].data = (void *)(long)i;
		ev_io_start(EV_A_ &(w_listen[i]));
		LOG("starting ioserver at %s:%s", conf.server[i].address, conf.server[i].port);
	}

	// 切换用户
	if (setuser(conf.user, conf.group) != 0)
	{
		ERROR("setuser");
	}

	// 执行事件循环
	ev_run(EV_A_ 0);

	// 退出
	LOG("Exit");
	mem_destroy();
	for (int i = 0; i < conf.server_num; i++)
	{
		close(sock_listen[i]);
	}

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

	ctx_t *ctx = (ctx_t *)mem_new(sizeof(ctx_t));
	if (ctx == NULL)
	{
		LOG("out of memory");
		return;
	}
	ctx->sock_local = accept(w->fd, NULL, NULL);
	if (ctx->sock_local < 0)
	{
		ERROR("accept");
		mem_delete(ctx);
		return;
	}
	setnonblock(ctx->sock_local);
	settimeout(ctx->sock_local);
	setkeepalive(ctx->sock_local);
	ctx->server_id = (int)(long)(w->data);
	ev_io_init(&ctx->w_local_read, iosocks_recv_cb, ctx->sock_local, EV_READ);
	ctx->w_local_read.data = (void *)ctx;
	ev_io_start(EV_A_ &ctx->w_local_read);
}

static void iosocks_recv_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ev_io_stop(EV_A_ w);

	ctx->tx_bytes = recv(ctx->sock_local, ctx->tx_buf, BUF_SIZE, 0);
	if (ctx->tx_bytes != 512)
	{
		if (ctx->tx_bytes < 0)
		{
			ERROR("recv");
		}
		else
		{
			LOG("bad client");
		}
		close(ctx->sock_local);
		mem_delete(ctx);
		return;
	}

	// IoSocks Request
	// +-------+------+------+------+
	// | MAGIC | HOST | PORT |  IV  |
	// +-------+------+------+------+
	// |   4   | 257  |  15  | 236  |
	// +-------+------+------+------+
	uint8_t key[64];
	memcpy(ctx->rx_buf, ctx->tx_buf + 276, 236);
	memcpy(ctx->rx_buf + 236, servers[ctx->server_id].key, servers[ctx->server_id].key_len);
	sha512(key, ctx->rx_buf, 236 + servers[ctx->server_id].key_len);
	enc_init(&ctx->enc_evp, enc_rc4, key, 64);
	io_decrypt(ctx->tx_buf, 276, &ctx->enc_evp);
	if (ntohl(*((uint32_t *)(ctx->tx_buf))) != MAGIC)
	{
		LOG("illegal client");
		close(ctx->sock_local);
		mem_delete(ctx);
		return;
	}
	char *host = (char *)ctx->tx_buf + 4;
	char *port = (char *)ctx->tx_buf + 261;
	host[256] = '\0';
	port[14] = '\0';
	LOG("connect %s:%s", host, port);
	ctx->gai = (gai_t *)(ctx->rx_buf);
	bzero(ctx->gai, sizeof(gai_t));
	ctx->gai->hints.ai_family = AF_UNSPEC;
	ctx->gai->hints.ai_socktype = SOCK_STREAM;
	strcpy(ctx->gai->host, host);
	strcpy(ctx->gai->port, port);
	ctx->gai->req.ar_name = ctx->gai->host;
	ctx->gai->req.ar_service = ctx->gai->port;
	ctx->gai->req.ar_request = &(ctx->gai->hints);
	ctx->gai->req.ar_result = NULL;
	ctx->resolv_tried = 0;
	emit_resolv(ctx);
}

static void emit_resolv(ctx_t *ctx)
{
	struct gaicb *req_ptr = &(ctx->gai->req);
	struct sigevent sevp;
	sevp.sigev_notify = SIGEV_SIGNAL;
	sevp.sigev_signo = SIGIO;
	sevp.sigev_value.sival_ptr = (void *)ctx;
	if (getaddrinfo_a(GAI_NOWAIT, &req_ptr, 1, &sevp) != 0)
	{
		ERROR("getaddrinfo_a");
		close(ctx->sock_local);
		mem_delete(ctx);
		return;
	}
	ctx->resolv_tried++;
}

static void resolv_cb(int signo, siginfo_t *info, void *context)
{
	ctx_t *ctx = (ctx_t *)info->si_value.sival_ptr;

	UNUSED(context);
	assert(signo == SIGIO);
	assert(ctx != NULL);

	if (gai_error(&ctx->gai->req) == 0)
	{
		// 域名解析成功，建立远程连接
		ctx->gai->res = ctx->gai->req.ar_result;
		ctx->sock_remote = socket(ctx->gai->res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (ctx->sock_remote < 0)
		{
			ERROR("socket");
			close(ctx->sock_local);
			mem_delete(ctx);
			return;
		}
		setnonblock(ctx->sock_remote);
		settimeout(ctx->sock_remote);
		setkeepalive(ctx->sock_remote);
		ev_io_init(&ctx->w_remote_write, connect_cb, ctx->sock_remote, EV_WRITE);
		ctx->w_remote_write.data = (void *)ctx;
		ev_io_start(EV_A_ &ctx->w_remote_write);
		connect(ctx->sock_remote, (struct sockaddr *)ctx->gai->res->ai_addr, ctx->gai->res->ai_addrlen);
	}
	else
	{
		// 域名解析失败
		if (ctx->resolv_tried < MAX_TRY)
		{
			LOG("failed to resolv host: %s, try again", ctx->gai->host);
			emit_resolv(ctx);
		}
		else
		{
			LOG("failed to resolv host: %s, abort", ctx->gai->host);
			close(ctx->sock_local);
			mem_delete(ctx);
		}
	}
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
		freeaddrinfo(ctx->gai->req.ar_result);
		ev_io_init(&ctx->w_local_read, local_read_cb, ctx->sock_local, EV_READ);
		ev_io_init(&ctx->w_local_write, local_write_cb, ctx->sock_local, EV_WRITE);
		ev_io_init(&ctx->w_remote_read, remote_read_cb, ctx->sock_remote, EV_READ);
		ev_io_init(&ctx->w_remote_write, remote_write_cb, ctx->sock_remote, EV_WRITE);
		ctx->w_local_read.data = (void *)ctx;
		ctx->w_local_write.data = (void *)ctx;
		ctx->w_remote_read.data = (void *)ctx;
		ctx->w_remote_write.data = (void *)ctx;
		if (ctx->tx_bytes > 512)
		{
			ctx->tx_offset = 512;
			ctx->tx_bytes -= 512;
			io_decrypt(ctx->tx_buf + ctx->tx_offset, ctx->tx_bytes, &ctx->enc_evp);
			ev_io_start(EV_A_ &ctx->w_remote_write);
		}
		else
		{
			ev_io_start(EV_A_ &ctx->w_local_read);
		}
		ev_io_start(EV_A_ &ctx->w_remote_read);
	}
	else
	{
		// 连接失败
		close(ctx->sock_remote);
		ctx->gai->res = ctx->gai->res->ai_next;
		if (ctx->gai->res != NULL)
		{
			// 尝试连接下一个地址
			ctx->sock_remote = socket(ctx->gai->res->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if (ctx->sock_remote < 0)
			{
				ERROR("socket");
				close(ctx->sock_local);
				freeaddrinfo(ctx->gai->req.ar_result);
				mem_delete(ctx);
				return;
			}
			setnonblock(ctx->sock_remote);
			settimeout(ctx->sock_remote);
			setkeepalive(ctx->sock_remote);
			ev_io_init(&ctx->w_remote_write, connect_cb, ctx->sock_remote, EV_WRITE);
			ctx->w_remote_write.data = (void *)ctx;
			ev_io_start(EV_A_ &ctx->w_remote_write);
			connect(ctx->sock_remote, (struct sockaddr *)ctx->gai->res->ai_addr, ctx->gai->res->ai_addrlen);
		}
		else
		{
			// 所有连接尝试均失败
			LOG("connect failed");
			close(ctx->sock_local);
			freeaddrinfo(ctx->gai->req.ar_result);
			mem_delete(ctx);
		}
	}
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
	io_decrypt(ctx->tx_buf, ctx->tx_bytes, &ctx->enc_evp);
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
	ev_io_stop(EV_A_ w);
	ev_io_start(EV_A_ &ctx->w_remote_write);
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
		ev_io_stop(EV_A_ w);
		ev_io_start(EV_A_ &ctx->w_remote_read);
	}
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	UNUSED(revents);

	ctx_t *ctx = (ctx_t *)(w->data);

	assert(ctx != NULL);

	ctx->rx_bytes = recv(ctx->sock_remote, ctx->rx_buf, BUF_SIZE, 0);
	if (ctx->rx_bytes <= 0)
	{
		if (ctx->rx_bytes < 0)
		{
			LOG("remote server reset");
		}
		cleanup(EV_A_ ctx);
		return;
	}
	io_encrypt(ctx->rx_buf, ctx->rx_bytes, &ctx->enc_evp);
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
	ev_io_stop(EV_A_ w);
	ev_io_start(EV_A_ &ctx->w_local_write);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	UNUSED(revents);

	ctx_t *ctx = (ctx_t *)(w->data);

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
		ev_io_stop(EV_A_ w);
		ev_io_start(EV_A_ &ctx->w_local_read);
	}
}

static void cleanup(EV_P_ ctx_t *ctx)
{
	ev_io_stop(EV_A_ &ctx->w_local_read);
	ev_io_stop(EV_A_ &ctx->w_local_write);
	ev_io_stop(EV_A_ &ctx->w_remote_read);
	ev_io_stop(EV_A_ &ctx->w_remote_write);
	close(ctx->sock_local);
	close(ctx->sock_remote);
	mem_delete(ctx);
}
