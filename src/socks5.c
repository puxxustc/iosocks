/*
 * socks5.c - SOCKS5 Protocol
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
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "log.h"
#include "socks5.h"
#include "utils.h"

#define UNUSED(x) do {(void)(x);} while (0)
#define BUF_SIZE 264

typedef enum
{
	CLOSED = 0,
	HELLO_RCVD,
	HELLO_ERR,
	HELLO_SENT,
	REQ_RCVD,
	REQ_ERR
} state_t;

typedef struct
{
	int sock;
	state_t state;
	int len;
	void (*cb)(int, char *, char *);
	ev_io w_read;
	ev_io w_write;
	char host[257];
	char port[15];
	uint8_t buf[BUF_SIZE];
} ctx_t;

static void socks5_send_cb(EV_P_ ev_io *w, int revents);
static void socks5_recv_cb(EV_P_ ev_io *w, int revents);

extern struct ev_loop *loop;

void socks5_accept(int sock, void (*cb)(int, char *, char *))
{
	ctx_t *ctx = (ctx_t *)malloc(sizeof(ctx_t));
	if (ctx == NULL)
	{
		LOG("out of memory");
		close(sock);
		return;
	}
	ctx->sock = sock;
	ctx->cb = cb;
	ctx->state = CLOSED;

	ev_io_init(&(ctx->w_read), socks5_recv_cb, ctx->sock, EV_READ);
	ev_io_init(&(ctx->w_write), socks5_send_cb, ctx->sock, EV_WRITE);
	ctx->w_read.data = (void *)ctx;
	ctx->w_write.data = (void *)ctx;

	ev_io_start(EV_A_ &(ctx->w_read));
}

static void socks5_recv_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ev_io_stop(EV_A_ w);

	bzero(ctx->buf, BUF_SIZE);
	ssize_t n = recv(ctx->sock, ctx->buf, BUF_SIZE, 0);
	if (n <= 0)
	{
		if (n < 0)
		{
			LOG("client reset");
		}
		close(ctx->sock);
		free(ctx);
		return;
	}

	switch (ctx->state)
	{
	case CLOSED:
	{
		// SOCKS5 HELLO
		// +-----+----------+----------+
		// | VER | NMETHODS | METHODS  |
		// +-----+----------+----------+
		// |  1  |    1     | 1 to 255 |
		// +-----+----------+----------+
		int error = 0;
		if (ctx->buf[0] != 0x05)
		{
			error = 1;
		}
		uint8_t nmethods = ctx->buf[1];
		uint8_t i;
		for (i = 0; i < nmethods; i++)
		{
			if (ctx->buf[2 + i] == 0x00)
			{
				break;
			}
		}
		if (i >= nmethods)
		{
			error = 2;
		}
		// SOCKS5 HELLO
		// +-----+--------+
		// | VER | METHOD |
		// +-----+--------+
		// |  1  |   1    |
		// +-----+--------+
		ctx->buf[0] = 0x05;
		ctx->buf[1] = 0x00;
		ctx->len = 2;
		ctx->state = HELLO_RCVD;
		if (error != 0)
		{
			ctx->state = HELLO_ERR;
			ctx->buf[1] = 0xff;
		}
		ev_io_start(EV_A_ &(ctx->w_write));
		break;
	}
	case HELLO_SENT:
	{
		// SOCKS5 REQUEST
		// +-----+-----+-------+------+----------+----------+
		// | VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		// +-----+-----+-------+------+----------+----------+
		// |  1  |  1  | X'00' |  1   | Variable |    2     |
		// +-----+-----+-------+------+----------+----------+
		int error = 0;
		if (ctx->buf[0] != 0x05)
		{
			error = 1;
		}
		if (ctx->buf[1] != 0x01)
		{
			// 只支持 CONNECT 命令
			error = 2;
		}
		if (ctx->buf[3] == 0x01)
		{
			// IPv4 地址
			inet_ntop(AF_INET, (const void *)(ctx->buf + 4), ctx->host,
			          INET_ADDRSTRLEN);
			sprintf(ctx->port, "%u", ntohs(*(uint16_t *)(ctx->buf + 8)));
		}
		else if (ctx->buf[3] == 0x03)
		{
			// 域名
			memcpy(ctx->host, ctx->buf + 5, ctx->buf[4]);
			ctx->host[ctx->buf[4]] = '\0';
			sprintf(ctx->port, "%u",
			        ntohs(*(uint16_t *)(ctx->buf + ctx->buf[4] + 5)));
		}
		else if (ctx->buf[3] == 0x04)
		{
			// IPv6 地址
			inet_ntop(AF_INET6, (const void *)(ctx->buf + 4), ctx->host,
			          INET6_ADDRSTRLEN);
			sprintf(ctx->port, "%u", ntohs(*(uint16_t *)(ctx->buf + 20)));
		}
		else
		{
			// 不支持的地址类型
			error = 3;
		}

		// SOCKS5 REPLY
		// +-----+-----+-------+------+----------+----------+
		// | VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +-----+-----+-------+------+----------+----------+
		// |  1  |  1  | X'00' |  1   | Variable |    2     |
		// +-----+-----+-------+------+----------+----------+
		bzero(ctx->buf, 10);
		ctx->buf[0] = 0x05;
		if (error == 0)
		{
			ctx->buf[1] = 0x00;
		}
		else if (error == 1)
		{
			ctx->buf[1] = 0x01;
		}
		else if (error == 2)
		{
			ctx->buf[1] = 0x07;
		}
		else
		{
			ctx->buf[1] = 0x08;
		}
		ctx->buf[2] = 0x00;
		ctx->buf[3] = 0x01;
		ctx->len = 10;
		ctx->state = REQ_RCVD;
		if (error != 0)
		{
			ctx->state = REQ_ERR;
		}
		ev_io_start(EV_A_ &ctx->w_write);
		break;
	}
	default:
	{
		// 不应该来到这里
		assert(0 != 0);
		break;
	}
	}
}

static void socks5_send_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);

	ev_io_stop(EV_A_ w);

	ssize_t n = send(ctx->sock, ctx->buf, ctx->len, MSG_NOSIGNAL);
	if (n != ctx->len)
	{
		if (n < 0)
		{
			ERROR("send");
		}
		close(ctx->sock);
		free(ctx);
		return;
	}

	switch (ctx->state)
	{
	case HELLO_RCVD:
	case HELLO_ERR:
	{
		if (ctx->state == HELLO_RCVD)
		{
			ctx->state = HELLO_SENT;
			ev_io_start(EV_A_ &(ctx->w_read));
		}
		else
		{
			close(ctx->sock);
			free(ctx);
		}
		break;
	}
	case REQ_RCVD:
	case REQ_ERR:
	{
		if (ctx->state == REQ_RCVD)
		{
			(ctx->cb)(ctx->sock, ctx->host, ctx->port);
			free(ctx);
		}
		else
		{
			close(ctx->sock);
			free(ctx);
		}
		break;
	}
	default:
	{
		// 不应该来到这里
		assert(0 != 0);
		break;
	}
	}
}
