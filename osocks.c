/*
 * osocks.c - iosocks server
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ev.h>
#include "log.h"
#include "mem.h"
#include "md5.h"
#include "encrypt.h"

// 缓冲区大小
#define BUF_SIZE 8192

// 魔数
#define MAGIC 0x526f6e61

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

// 连接状态
typedef enum
{
	CLOSED = 0,
	REQ_RCVD,
	REQ_ERR,
	CONNECTED,
	ESTAB,
	CLOSE_WAIT
} state_t;

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
	struct addrinfo *addr;
	int sock_local;
	int sock_remote;
	state_t state;
	enc_evp_t enc_evp;
	uint8_t rx_buf[BUF_SIZE];
	uint8_t tx_buf[BUF_SIZE];
} conn_t;


static void help(void);
static void sigint_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static void closewait_cb(EV_P_ ev_timer *w, int revents);
static bool setnonblock(int sock);
static bool settimeout(int sock);
static void cleanup(EV_P_ conn_t *conn);

// 服务器的信息
struct
{
	const char *key;
	size_t key_len;
} server = { .key = NULL, .key_len = 0};


int main(int argc, char **argv)
{
	const char *server_addr = "0.0.0.0";
	const char *server_port = "8388";

	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
		{
			help();
			return 0;
		}
		else if (strcmp(argv[i], "-s") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			server_addr = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-p") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			server_port = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-k") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			server.key = argv[i + 1];
			server.key_len = strlen(server.key);
			if (server.key_len > 255)
			{
				fprintf(stderr, "Key too long\n");
				return 1;
			}
			i++;

		}
		else
		{
			fprintf(stderr, "Invalid option: %s\n", argv[i]);
			return 1;
		}
	}
	if ((server_addr == NULL) || (server_port == NULL) || (server.key == NULL))
	{
		help();
		return 1;
	}

	// 初始化本地监听 socket
	struct addrinfo hints;
	struct addrinfo *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(server_addr, server_port, &hints, &res) != 0)
	{
		LOG("Wrong server_host/server_port");
		return 2;
	}
	int sock_listen = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock_listen < 0)
	{
		ERR("socket");
		return 2;
	}
	setnonblock(sock_listen);
	int sockopt = 1;
	if (setsockopt(sock_listen, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int)) != 0)
	{
		ERR("setsockopt SO_REUSEADDR");
		return 2;
	}
	if (bind(sock_listen, (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
	{
		ERR("bind");
		return 2;
	}
	freeaddrinfo(res);
	if (listen(sock_listen, 1024) != 0)
	{
		ERR("listen");
		return 2;
	}

	// 初始化内存池
	size_t block_size[2] = { sizeof(ev_timer), sizeof(conn_t) };
	size_t block_count[2] = { 8, 64 };
	if (!mem_init(block_size, block_count, 2))
	{
		LOG("memory pool error");
		return 3;
	}

	// 初始化 ev
	struct ev_loop *loop = EV_DEFAULT;
	ev_signal w_sigint;
	ev_signal_init(&w_sigint, sigint_cb, SIGINT);
	ev_signal_start(loop, &w_sigint);
	ev_io w_listen;
	ev_io_init(&w_listen, accept_cb, sock_listen, EV_READ);
	ev_io_start(loop, &w_listen);

	// 执行事件循环
	LOG("starting osocks at %s:%s", server_addr, server_port);
	ev_run(loop, 0);

	// 退出
	LOG("Exit");

	return 0;
}

static void help(void)
{
	printf("usage: osocks\n"
		   "  -h, --help          show this help\n"
		   "  -s <server_addr>    server address, default: 0.0.0.0\n"
		   "  -p <server_port>    server port, default: 8388\n"
		   "  -k <key>            encryption key\n"
		   "");
}

static void sigint_cb(EV_P_ ev_signal *w, int revents)
{
	LOG("SIGINT");
	ev_break(EV_A_ EVBREAK_ALL);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)mem_new(sizeof(conn_t));
	if (conn == NULL)
	{
		return;
	}
	conn->sock_local = accept(w->fd, NULL, NULL);
	if (conn->sock_local < 0)
	{
		ERR("accept");
		mem_delete(conn);
		return;
	}
	if (!setnonblock(conn->sock_local))
	{
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}
	conn->state = CLOSED;
	ev_io_init(&conn->w_local_read, local_read_cb, conn->sock_local, EV_READ);
	ev_io_init(&conn->w_local_write, local_write_cb, conn->sock_local, EV_WRITE);
	conn->w_local_read.data = (void *)conn;
	conn->w_local_write.data = (void *)conn;
	ev_io_start(EV_A_ &conn->w_local_read);
}

static void local_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	if (conn->state != ESTAB)
	{
		ev_io_stop(EV_A_ w);
	}

	switch (conn->state)
	{
	case CLOSED:
	{
		// iosocks 请求
		// +-------+------+------+------+
		// | MAGIC | HOST | PORT |  IV  |
		// +-------+------+------+------+
		// |   4   | 257  |  15  | 236  |
		// +-------+------+------+------+
		uint8_t key[64];
		ssize_t rx_bytes = recv(conn->sock_local, conn->rx_buf, BUF_SIZE, 0);
		if (rx_bytes != 512)
		{
			if (rx_bytes < 0)
			{
#ifndef NDEBUG
				ERR("recv");
#endif
				LOG("client reset");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		memcpy(conn->tx_buf, conn->rx_buf + 276, 236);
		memcpy(conn->tx_buf + 236, server.key, server.key_len);
		md5(conn->tx_buf, 236 + server.key_len, key);
		md5(key, 16, key + 16);
		md5(key, 32, key + 32);
		md5(key, 48, key + 48);
		enc_init(&conn->enc_evp, enc_rc4, key, 64);
		io_decrypt(conn->rx_buf, 276, &conn->enc_evp);
		uint32_t magic = ntohl(*((uint32_t *)(conn->rx_buf)));
		const char *host = (const char *)conn->rx_buf + 4;
		const char *port = (const char *)conn->rx_buf + 261;
		conn->rx_buf[260] = 0;
		conn->rx_buf[275] = 0;
		LOG("connect %s:%s", host, port);
		struct addrinfo hints;
		bzero(&hints, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		if ((magic != MAGIC) || (getaddrinfo(host, port, &hints, &conn->addr) != 0))
		{
			if (magic != MAGIC)
			{
				LOG("illegal client");
				close(conn->sock_local);
				mem_delete(conn);
				return;
			}
			else
			{
				LOG("can not resolv host: %s", host);
				// iosocks 应答
				// +-------+
				// | MAGIC |
				// +-------+
				// |   4   |
				// +-------+
				bzero(conn->tx_buf, 4);
				conn->tx_bytes = 4;
				io_encrypt(conn->tx_buf, conn->tx_bytes, &conn->enc_evp);
				conn->state = REQ_ERR;
				ev_io_start(EV_A_ &conn->w_local_write);
			}
		}
		else
		{
			// 建立远程连接
			conn->sock_remote = socket(conn->addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if (conn->sock_remote < 0)
			{
				ERR("socket");
				freeaddrinfo(conn->addr);
				close(conn->sock_local);
				mem_delete(conn);
				return;
			}
			setnonblock(conn->sock_remote);
			settimeout(conn->sock_remote);
			ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
			conn->w_remote_write.data = (void *)conn;
			ev_io_start(EV_A_ &conn->w_remote_write);
			conn->state = REQ_RCVD;
			connect(conn->sock_remote, (struct sockaddr *)conn->addr->ai_addr, conn->addr->ai_addrlen);
		}
		break;
	}
	case ESTAB:
	{
		conn->tx_bytes = recv(conn->sock_local, conn->tx_buf, BUF_SIZE, 0);
		if (conn->tx_bytes <= 0)
		{
			if (conn->tx_bytes < 0)
			{
#ifndef NDEBUG
				ERR("recv");
#endif
				LOG("client reset");
			}
			cleanup(EV_A_ conn);
			return;
		}
		io_decrypt(conn->tx_buf, conn->tx_bytes, &conn->enc_evp);
		ssize_t n = send(conn->sock_remote, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (n < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			{
				conn->tx_offset = 0;
			}
			else
			{
				ERR("send");
				cleanup(EV_A_ conn);
				return;
			}
		}
		else if (n < conn->tx_bytes)
		{
			conn->tx_offset = n;
			conn->tx_bytes -= n;
		}
		else
		{
			return;
		}
		ev_io_start(EV_A_ &conn->w_remote_write);
		ev_io_stop(EV_A_ w);
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

static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)w->data;

	if (conn->state != ESTAB)
	{
		ev_io_stop(EV_A_ w);
	}

	switch (conn->state)
	{
	case REQ_ERR:
	case CONNECTED:
	{
		ssize_t tx_bytes = send(conn->sock_local, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (tx_bytes != conn->tx_bytes)
		{
			if (tx_bytes < 0)
			{
				ERR("send");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		if (conn->state == CONNECTED)
		{
			conn->state = ESTAB;
			ev_io_init(&conn->w_remote_read, remote_read_cb, conn->sock_remote, EV_READ);
			ev_io_init(&conn->w_remote_write, remote_write_cb, conn->sock_remote, EV_WRITE);
			conn->w_remote_read.data = (void *)conn;
			conn->w_remote_write.data = (void *)conn;
			ev_io_start(EV_A_ &conn->w_local_read);
			ev_io_start(EV_A_ &conn->w_remote_read);
		}
		else
		{
			conn->state = CLOSE_WAIT;
			ev_timer *w_timer = (ev_timer *)mem_new(sizeof(ev_timer));
			if (w_timer == NULL)
			{
				close(conn->sock_local);
				mem_delete(conn);
				return;
			}
			ev_timer_init(w_timer, closewait_cb, 1.0, 0);
			w_timer->data = (void *)conn;
			ev_timer_start(EV_A_ w_timer);
		}
		break;
	}
	case ESTAB:
	{
		assert(conn->rx_bytes > 0);
		ssize_t n = send(conn->sock_local, conn->rx_buf + conn->rx_offset, conn->rx_bytes, MSG_NOSIGNAL);
		if (n < 0)
		{
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
			{
				return;
			}
			else
			{
				ERR("send");
				cleanup(EV_A_ conn);
				return;
			}
		}
		else if (n < conn->rx_bytes)
		{
			conn->rx_offset += n;
			conn->rx_bytes -= n;
		}
		else
		{
			ev_io_start(EV_A_ &conn->w_remote_read);
			ev_io_stop(EV_A_ w);
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

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn->state == ESTAB);

	conn->rx_bytes = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
	if (conn->rx_bytes <= 0)
	{
		if (conn->rx_bytes < 0)
		{
#ifndef NDEBUG
			ERR("recv");
#endif
			LOG("remote server reset");
		}
		cleanup(EV_A_ conn);
		return;
	}
	io_encrypt(conn->rx_buf, conn->rx_bytes, &conn->enc_evp);
	ssize_t n = send(conn->sock_local, conn->rx_buf, conn->rx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			conn->rx_offset = 0;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->rx_bytes)
	{
		conn->rx_offset = n;
		conn->rx_bytes -= n;
	}
	else
	{
		return;
	}
	ev_io_start(EV_A_ &conn->w_local_write);
	ev_io_stop(EV_A_ w);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn->state == ESTAB);
	assert(conn->tx_bytes > 0);

	ssize_t n = send(conn->sock_remote, conn->tx_buf + conn->tx_offset, conn->tx_bytes, MSG_NOSIGNAL);
	if (n < 0)
	{
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		{
			return;
		}
		else
		{
			ERR("send");
			cleanup(EV_A_ conn);
			return;
		}
	}
	else if (n < conn->tx_bytes)
	{
		conn->tx_offset += n;
		conn->tx_bytes -= n;
	}
	else
	{
		ev_io_start(EV_A_ &conn->w_local_read);
		ev_io_stop(EV_A_ w);
	}
}

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn->state == REQ_RCVD);

	ev_io_stop(EV_A_ w);

	int error = 1;
	socklen_t len = sizeof(int);
	getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &error, &len);

	// iosocks 应答
	// +-------+
	// | MAGIC |
	// +-------+
	// |   4   |
	// +-------+
	if (error == 0)
	{
		// 连接成功
		*((uint32_t *)(conn->tx_buf)) = htonl(MAGIC);
		conn->state = CONNECTED;
	}
	else
	{
		// 连接失败
		close(conn->sock_remote);
		conn->addr = conn->addr->ai_next;
		if (conn->addr != NULL)
		{
			conn->sock_remote = socket(conn->addr->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if (conn->sock_remote < 0)
			{
				ERR("socket");
				freeaddrinfo(conn->addr);
				close(conn->sock_local);
				mem_delete(conn);
				return;
			}
			setnonblock(conn->sock_remote);
			settimeout(conn->sock_remote);
			ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
			conn->w_remote_write.data = (void *)conn;
			ev_io_start(EV_A_ &conn->w_remote_write);
			connect(conn->sock_remote, (struct sockaddr *)conn->addr->ai_addr, conn->addr->ai_addrlen);
			return;
		}
		else
		{
			LOG("connect failed");
			close(conn->sock_remote);
			*((uint32_t *)(conn->tx_buf)) = 0;
			conn->state = REQ_ERR;
		}
	}
	freeaddrinfo(conn->addr);
	conn->tx_bytes = 4;
	io_encrypt(conn->tx_buf, conn->tx_bytes, &conn->enc_evp);
	ev_io_stop(EV_A_ w);
	ev_io_start(EV_A_ &conn->w_local_write);
}

static void closewait_cb(EV_P_ ev_timer *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);
	ev_timer_stop(EV_A_ w);
	close(conn->sock_local);
	mem_delete(w);
	mem_delete(conn);
}

static bool setnonblock(int sock)
{
	int flags;
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1)
	{
		return false;
	}
	if (-1 == fcntl(sock, F_SETFL, flags | O_NONBLOCK))
	{
		return false;
	}
	return true;
}

static bool settimeout(int sock)
{
	struct timeval timeout = { .tv_sec = 10, .tv_usec = 0};
	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return false;
	}
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) != 0)
	{
		return false;
	}
	return true;
}

static void cleanup(EV_P_ conn_t *conn)
{
	ev_io_stop(EV_A_ &conn->w_local_read);
	ev_io_stop(EV_A_ &conn->w_local_write);
	ev_io_stop(EV_A_ &conn->w_remote_read);
	ev_io_stop(EV_A_ &conn->w_remote_write);
	close(conn->sock_local);
	close(conn->sock_remote);
	mem_delete(conn);
}
