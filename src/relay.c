/*
 * relay.c - TCP relay
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
#include <errno.h>
#include <ev.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "crypto.h"
#include "log.h"
#include "relay.h"

#define UNUSED(x) do {(void)(x);} while (0)

// 缓冲区大小
#define BUF_SIZE 8192

#ifndef EAGAIN
#  define EAGAIN EWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#  define EWOULDBLOCK EAGAIN
#endif

typedef struct
{
	int sock_local;
	int sock_remote;
	ssize_t rx_bytes;
	ssize_t rx_offset;
	ssize_t tx_bytes;
	ssize_t tx_offset;
	crypto_evp_t evp;
	ev_io w_local_read;
	ev_io w_local_write;
	ev_io w_remote_read;
	ev_io w_remote_write;
	uint8_t rx_buf[BUF_SIZE];
	uint8_t tx_buf[BUF_SIZE];
} ctx_t;

static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static void cleanup(EV_P_ ctx_t *ctx);

extern struct ev_loop *loop;

void relay(int local, int remote, crypto_evp_t *evp)
{
	ctx_t *ctx = (ctx_t *)malloc(sizeof(ctx_t));
	if (ctx == NULL)
	{
		LOG("out of memory");
		close(local);
		close(remote);
		return;
	}
	ctx->sock_local = local;
	ctx->sock_remote = remote;
	ctx->evp = *evp;

	ev_io_init(&(ctx->w_local_read), local_read_cb, ctx->sock_local, EV_READ);
	ev_io_init(&(ctx->w_local_write), local_write_cb, ctx->sock_local, EV_WRITE);
	ev_io_init(&(ctx->w_remote_read), remote_read_cb, ctx->sock_remote, EV_READ);
	ev_io_init(&(ctx->w_remote_write), remote_write_cb, ctx->sock_remote, EV_WRITE);
	ctx->w_local_read.data = (void *)ctx;
	ctx->w_local_write.data = (void *)ctx;
	ctx->w_remote_read.data = (void *)ctx;
	ctx->w_remote_write.data = (void *)ctx;
	ev_io_start(EV_A_ &(ctx->w_local_read));
	ev_io_start(EV_A_ &(ctx->w_remote_read));
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
	crypto_encrypt(ctx->tx_buf, ctx->tx_bytes, &(ctx->evp));
	ssize_t n = send(ctx->sock_remote, ctx->tx_buf,
	                 ctx->tx_bytes, MSG_NOSIGNAL);
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
	ev_io_start(EV_A_ &(ctx->w_remote_write));
	ev_io_stop(EV_A_ w);
}

static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);
	assert(ctx->rx_bytes > 0);

	ssize_t n = send(ctx->sock_local, ctx->rx_buf + ctx->rx_offset,
	                 ctx->rx_bytes, MSG_NOSIGNAL);
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
		ev_io_start(EV_A_ &(ctx->w_remote_read));
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
	crypto_decrypt(ctx->rx_buf, ctx->rx_bytes, &(ctx->evp));
	ssize_t n = send(ctx->sock_local, ctx->rx_buf,
	                 ctx->rx_bytes, MSG_NOSIGNAL);
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
	ev_io_start(EV_A_ &(ctx->w_local_write));
	ev_io_stop(EV_A_ w);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	ctx_t *ctx = (ctx_t *)(w->data);

	UNUSED(revents);
	assert(ctx != NULL);
	assert(ctx->tx_bytes > 0);

	ev_io_stop(EV_A_ w);

	ssize_t n = send(ctx->sock_remote, ctx->tx_buf + ctx->tx_offset,
	                 ctx->tx_bytes, MSG_NOSIGNAL);
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
		ev_io_start(EV_A_ &(ctx->w_local_read));
		ev_io_stop(EV_A_ w);
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
	free(ctx);
}
