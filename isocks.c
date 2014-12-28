/*
 * isocks.c - iosocks client
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

// 错误类型
typedef enum
{
	ERR_OK = 0,
	ERR_ADDR = 1,
	ERR_CMD = 2,
	ERR_NET = 3,
	ERR_CONN = 4,
	ERR_NORMAL = 5
} error_t;

// 连接状态
typedef enum
{
	CLOSED = 0,
	NEGO_RCVD = 1,
	NEGO_SENT = 3,
	CMD_RCVD = 4,
	CMD_DONE = 5,
	ESTAB = 6,
	CLOSE_WAIT = 7
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
	int sock_local;
	int sock_remote;
	state_t state;
	bool error;
	uint8_t key[16];
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
static void rand_bytes(uint8_t *stream, size_t len);

// 服务器的信息
struct
{
	char addr[128];
	socklen_t addrlen;
	int family;
	const char *key;
	size_t key_len;
} server = { .key = NULL, .key_len = 0};


int main(int argc, char **argv)
{
	const char *server_host = NULL;
	const char *server_port = NULL;
	const char *local_address = "127.0.0.1";
	const char *local_port = "1080";

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
			server_host = argv[i + 1];
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
		else if (strcmp(argv[i], "-b") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			local_address = argv[i + 1];
			i++;
		}
		else if (strcmp(argv[i], "-l") == 0)
		{
			if (i + 2 > argc)
			{
				fprintf(stderr, "Invalid option: %s\n", argv[i]);
				return 1;
			}
			local_port = argv[i + 1];
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
			if (server.key_len > 271)
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
	if ((server_host == NULL) || (server_port == NULL) || (server.key == NULL))
	{
		help();
		return 1;
	}

	// 服务器信息
	struct addrinfo hints;
	struct addrinfo *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(server_host, server_port, &hints, &res) != 0)
	{
		LOG("Wrong server_host/server_port");
		return 2;
	}
	memcpy(server.addr, res->ai_addr, res->ai_addrlen);
	server.addrlen = res->ai_addrlen;
	server.family = res->ai_family;
	freeaddrinfo(res);

	// 初始化本地监听 socket
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(local_address, local_port, &hints, &res) != 0)
	{
		LOG("Wrong local_host/local_port");
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
	LOG("Starting isocks...");
	ev_run(loop, 0);

	// 退出
	LOG("Exit");

	return 0;
}

static void help(void)
{
	printf("usage: isocks\n"
		   "  -h, --help          show this help\n"
		   "  -s <server_host>    host name or ip address of your remote server\n"
		   "  -p <server_port>    port number of your remote server\n"
		   "  -b <local_address>  local address to bind (default 127.0.0.1)\n"
		   "  -l <local_port>     port number of your local server (default 1080)\n"
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
	conn->error = false;
	conn->sock_local = accept(w->fd, NULL, NULL);
	if (conn->sock_local < 0)
	{
		ERR("accept");
		mem_delete(conn);
		return;
	}
	setnonblock(conn->sock_local);
	conn->state = CLOSED;
	ev_io_init(&conn->w_local_read, local_read_cb, conn->sock_local, EV_READ);
	ev_io_init(&conn->w_local_write, local_write_cb, conn->sock_local, EV_WRITE);
	conn->w_local_read.data = (void *)conn;
	conn->w_local_write.data = (void *)conn;
	ev_io_start(EV_A_ &conn->w_local_read);
}

static void local_read_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conn_t *conn = (conn_t *)(w->data);

	switch (conn->state)
	{
	case CLOSED:
	{
		// 协商请求格式
		// +----+----------+----------+
		// |VER | NMETHODS | METHODS  |
		// +----+----------+----------+
		// | 1  |    1     | 1 to 255 |
		// +----+----------+----------+
		bzero(conn->rx_buf, 257);
		ssize_t rx_bytes = recv(conn->sock_local, conn->rx_buf, BUF_SIZE, 0);
		if (rx_bytes <= 0)
		{
			if (rx_bytes < 0)
			{
				ERR("recv");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		error_t err = ERR_OK;
		if (conn->rx_buf[0] != 0x05)
		{
			err = ERR_NORMAL;
		}
		uint8_t nmethods = conn->rx_buf[1];
		uint8_t i;
		for (i = 0; i < nmethods; i++)
		{
			if (conn->rx_buf[2 + i] == 0x00)
			{
				break;
			}
		}
		if (i >= nmethods)
		{
			err = ERR_NORMAL;
		}
		// 协商回应格式
		// +----+--------+
		// |VER | METHOD |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+
		conn->tx_buf[0] = 0x05;
		conn->tx_buf[1] = 0x00;
		if (err != ERR_OK)
		{
			conn->error = true;
			conn->tx_buf[1] = 0xff;
		}
		conn->tx_bytes = 2;
		conn->state = NEGO_RCVD;
		ev_io_start(EV_A_ &conn->w_local_write);
		break;
	}
	case NEGO_SENT:
	{
		// 命令请求格式
		// +----+-----+-------+------+----------+----------+
		// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		bzero(conn->rx_buf, 263);
		ssize_t rx_bytes = recv(conn->sock_local, conn->rx_buf, BUF_SIZE, 0);
		if (rx_bytes <= 0)
		{
			if (rx_bytes < 0)
			{
				ERR("recv");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		error_t err = ERR_OK;
		if (conn->rx_buf[0] != 0x05)
		{
			err = ERR_NORMAL;
		}
		if (conn->rx_buf[1] != 0x01)
		{
			// 暂时只支持 CONNECT 命令
			err = ERR_CMD;
		}
		char host[257], port[16];
		if (conn->rx_buf[3] == 0x01)
		{
			// IPv4 地址
			inet_ntop(AF_INET, (const void *)(conn->rx_buf + 4), host, INET_ADDRSTRLEN);
			sprintf(port, "%d", ntohs(*(uint16_t *)(conn->rx_buf + 8)));
		}
		else if (conn->rx_buf[3] == 0x03)
		{
			// 域名
			memcpy(host, conn->rx_buf + 5, conn->rx_buf[4]);
			host[conn->rx_buf[4]] = '\0';
			sprintf(port, "%d", ntohs(*(uint16_t *)(conn->rx_buf + conn->rx_buf[4] + 5)));
		}
		else if (conn->rx_buf[3] == 0x04)
		{
			// IPv6 地址
			inet_ntop(AF_INET6, (const void *)(conn->rx_buf + 4), host, INET6_ADDRSTRLEN);
			sprintf(port, "%d", ntohs(*(uint16_t *)(conn->rx_buf + 20)));
		}
		else
		{
			// 不支持的地址类型
			err = ERR_ADDR;
		}
		if (err != ERR_OK)
		{
			// 命令应答格式
			// +----+-----+-------+------+----------+----------+
			// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			// +----+-----+-------+------+----------+----------+
			// | 1  |  1  | X'00' |  1   | Variable |    2     |
			// +----+-----+-------+------+----------+----------+
			bzero(conn->tx_buf, 10);
			conn->tx_buf[0] = 0x05;
			if (err == ERR_CMD)
			{
				conn->tx_buf[1] = 0x07;
			}
			else if (err == ERR_ADDR)
			{
				conn->tx_buf[1] = 0x08;
			}
			else
			{
				conn->tx_buf[1] = 0x01;
			}
			conn->tx_buf[2] = 0x00;
			conn->tx_buf[3] = 0x01;
			conn->tx_bytes = 10;
			conn->error = true;
			conn->state = CMD_RCVD;
			ev_io_start(EV_A_ &conn->w_local_write);
		}
		else
		{
			LOG("connect %s:%s", host, port);
			// 准备要发送的数据
			// 命令格式
			// +------+------+------+
			// | HOST | PORT |  IV  |
			// +------+------+------+
			// | 257  |  15  | 240  |
			// +------+------+------+
			rand_bytes(conn->rx_buf, 240);
			memcpy(conn->rx_buf + 240, server.key, server.key_len);
			md5(conn->rx_buf, 240 + server.key_len, conn->key);
			memcpy(conn->tx_buf + 272, conn->rx_buf, 240);
			bzero(conn->tx_buf, 272);
			strcpy((char *)conn->tx_buf, host);
			strcpy((char *)conn->tx_buf + 257, port);
			encrypt(conn->tx_buf, 272, conn->key, 16);
			conn->tx_bytes = 512;
			// 建立远程连接
			conn->sock_remote = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
			if (conn->sock_remote < 0)
			{
				ERR("socket");
				close(conn->sock_local);
				mem_delete(conn);
				return;
			}
			setnonblock(conn->sock_remote);
			settimeout(conn->sock_remote);
			ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
			conn->w_remote_write.data = (void *)conn;
			conn->state = CMD_RCVD;
			ev_io_start(EV_A_ &conn->w_remote_write);
			connect(conn->sock_remote, (struct sockaddr *)server.addr, server.addrlen);
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
				ERR("recv");
			}
			ev_io_stop(EV_A_ &conn->w_local_write);
			ev_io_stop(EV_A_ &conn->w_remote_read);
			ev_io_stop(EV_A_ &conn->w_remote_write);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		encrypt(conn->tx_buf, conn->tx_bytes, conn->key, 16);
		ev_io_start(EV_A_ &conn->w_remote_write);
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
	ev_io_stop(EV_A_ w);

	conn_t *conn = (conn_t *)w->data;

	switch (conn->state)
	{
	case NEGO_RCVD:
	{
		ssize_t tx_bytes = send(conn->sock_local, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (tx_bytes <= 0)
		{
			if (tx_bytes < 0)
			{
				ERR("send");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		if (conn->error)
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
		else
		{
			conn->state = NEGO_SENT;
			ev_io_start(EV_A_ &conn->w_local_read);
		}
		break;
	}
	case CMD_DONE:
	{
		ssize_t tx_bytes = send(conn->sock_local, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (tx_bytes <= 0)
		{
			if (tx_bytes < 0)
			{
				ERR("send");
			}
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		if (conn->error)
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
		else
		{
			conn->state = ESTAB;
			ev_io_start(EV_A_ &conn->w_local_read);
			ev_io_start(EV_A_ &conn->w_remote_read);
		}
		break;
	}
	case ESTAB:
	{
		ssize_t n = send(conn->sock_local, conn->rx_buf, conn->rx_bytes, MSG_NOSIGNAL);
		if (n < 0)
		{
			ERR("send");
			ev_io_stop(EV_A_ &conn->w_local_read);
			ev_io_stop(EV_A_ &conn->w_remote_read);
			ev_io_stop(EV_A_ &conn->w_remote_write);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		ev_io_start(EV_A_ &conn->w_remote_read);
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

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conn_t *conn = (conn_t *)(w->data);
	int error = 0;
	socklen_t len = sizeof(int);

	getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &error, &len);

	if (error != 0)
	{
		// 命令应答格式
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		bzero(conn->tx_buf, 10);
		conn->tx_buf[0] = 0x05;
		conn->tx_buf[1] = 0x05;
		conn->tx_buf[2] = 0x00;
		conn->tx_buf[3] = 0x01;
		conn->tx_bytes = 10;
		conn->error = true;
		conn->state = CMD_RCVD;
		close(conn->sock_remote);
		ev_io_start(EV_A_ &conn->w_local_write);
	}
	conn->state = CMD_RCVD;
	ev_io_init(&conn->w_remote_write, remote_write_cb, conn->sock_remote, EV_WRITE);
	conn->w_remote_write.data = conn;
	ev_io_start(EV_A_ &conn->w_remote_write);
}

static void closewait_cb(EV_P_ ev_timer *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	ev_timer_stop(EV_A_ w);

	close(conn->sock_local);
	mem_delete(w);
	mem_delete(conn);
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	ev_io_stop(EV_A_ w);

	switch (conn->state)
	{
	case CMD_RCVD:
	{
		ssize_t n = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
		if (n <= 0)
		{
			if (n < 0)
			{
				ERR("recv");
			}
			ev_io_stop(EV_A_ &conn->w_local_read);
			ev_io_stop(EV_A_ &conn->w_local_write);
			ev_io_stop(EV_A_ &conn->w_remote_write);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		decrypt(conn->rx_buf, n, conn->key, 16);
		uint8_t digest[16];
		md5(conn->key, 16, digest);
		// 命令应答格式
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+
		bzero(conn->tx_buf, 10);
		conn->tx_buf[0] = 0x05;
		conn->tx_buf[1] = 0x00;
		conn->tx_buf[2] = 0x00;
		conn->tx_buf[3] = 0x01;
		conn->tx_bytes = 10;
		if (memcmp(digest, conn->rx_buf, 16) != 0)
		{
			conn->error = true;
			conn->tx_buf[1] = 0x05;
		}
		conn->state = CMD_DONE;
		ev_io_start(EV_A_ &conn->w_local_write);
		break;
	}
	case ESTAB:
	{
		conn->rx_bytes = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
		if (conn->rx_bytes <= 0)
		{
			if (conn->rx_bytes < 0)
			{
				ERR("recv");
			}
			ev_io_stop(EV_A_ &conn->w_local_read);
			ev_io_stop(EV_A_ &conn->w_local_write);
			ev_io_stop(EV_A_ &conn->w_remote_write);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		decrypt(conn->rx_buf, conn->rx_bytes, conn->key, 16);
		ev_io_start(EV_A_ &conn->w_local_write);
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

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	ev_io_stop(EV_A_ w);

	conn_t *conn = (conn_t *)(w->data);

	switch (conn->state)
	{
	case CMD_RCVD:
	{
		ssize_t n = send(conn->sock_remote, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (n < 0)
		{
			ERR("send");
			ev_io_stop(EV_A_ &conn->w_local_read);
			ev_io_stop(EV_A_ &conn->w_local_write);
			ev_io_stop(EV_A_ &conn->w_remote_read);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		ev_io_init(&conn->w_remote_read, remote_read_cb, conn->sock_remote, EV_READ);
		conn->w_remote_read.data = (void *)conn;
		ev_io_start(EV_A_ &conn->w_remote_read);
		break;
	}
	case ESTAB:
	{
		ssize_t n = send(conn->sock_remote, conn->tx_buf, conn->tx_bytes, MSG_NOSIGNAL);
		if (n < 0)
		{
			ERR("send");
			ev_io_stop(EV_A_ &conn->w_local_read);
			ev_io_stop(EV_A_ &conn->w_local_write);
			ev_io_stop(EV_A_ &conn->w_remote_read);
			close(conn->sock_local);
			close(conn->sock_remote);
			mem_delete(conn);
			return;
		}
		ev_io_start(EV_A_ &conn->w_local_read);
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
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0};
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

static void rand_bytes(uint8_t *stream, size_t len)
{
	static int urand = -1;
	if (urand == -1)
	{
		urand = open("/dev/urandom", O_RDONLY, 0);
	}
	read(urand, stream, len);
}
