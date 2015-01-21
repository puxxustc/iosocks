/*
 * ioserver.c - iosocks server
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
} conn_t;


static void help(void);
static void signal_cb(EV_P_ ev_signal *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void iosocks_recv_cb(EV_P_ ev_io *w, int revents);
static void emit_resolv(conn_t *conn);
static void local_read_cb(EV_P_ ev_io *w, int revents);
static void local_write_cb(EV_P_ ev_io *w, int revents);
static void remote_read_cb(EV_P_ ev_io *w, int revents);
static void remote_write_cb(EV_P_ ev_io *w, int revents);
static void resolv_cb(int signo, siginfo_t *info, void *context);
static void connect_cb(EV_P_ ev_io *w, int revents);
static void cleanup(EV_P_ conn_t *conn);

// 服务器的信息
typedef struct
{
	char *key;
	size_t key_len;
} server_t;
server_t servers[MAX_SERVER];

struct ev_loop *loop;

int main(int argc, char **argv)
{
	const char *conf_file = NULL;
	conf_t conf;
	bzero(&conf, sizeof(conf_t));

	// 处理命令行参数
	for (int i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
		{
			help();
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
		help();
		return 1;
	}
	if (read_conf(conf_file, &conf) != 0)
	{
		return 1;
	}
	if (conf.server_num == 0)
	{
		help();
		return 1;
	}
	for (int i = 0; i < conf.server_num; i++)
	{
		if (conf.server[i].key == NULL)
		{
			help();
			return 1;
		}
	}

	// 服务器信息
	for (int i = 0; i < conf.server_num; i++)
	{
		servers[i].key = conf.server[i].key;
		servers[i].key_len = strlen(servers[i].key);
		if (servers[i].key_len > 256)
		{
			servers[i].key[257] = '\0';
			servers[i].key_len = 256;
		}
	}

	// 初始化内存池
	size_t chunk_size[1] = { sizeof(conn_t) };
	size_t chunk_count[1] = { IOSERVER_CONN };
	if (mem_init(chunk_size, chunk_count, 1) != 0)
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

	// SIGUSR1 信号
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
			LOG("wrong server_host/server_port");
			return 4;
		}
		sock_listen[i] = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (sock_listen[i] < 0)
		{
			ERR("socket");
			return 4;
		}
		setnonblock(sock_listen[i]);
		setreuseaddr(sock_listen[i]);
		if (bind(sock_listen[i], (struct sockaddr *)res->ai_addr, res->ai_addrlen) != 0)
		{
			ERR("bind");
			return 4;
		}
		freeaddrinfo(res);
		if (listen(sock_listen[i], 1024) != 0)
		{
			ERR("listen");
			return 4;
		}
		ev_io_init(&(w_listen[i]), accept_cb, sock_listen[i], EV_READ);
		w_listen[i].data = (void *)(long)i;
		ev_io_start(EV_A_ &(w_listen[i]));
		LOG("starting ioserver at %s:%s", conf.server[i].address, conf.server[i].port);
	}

	// 切换用户
	if ((conf.user != NULL) || (conf.group != NULL))
	{
		if (setuser(conf.user, conf.group) != 0)
		{
			LOG("warning: failed to set user/group");
		}
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

	return 0;
}

static void help(void)
{
	printf("usage: ioserver\n"
	       "  -h, --help        show this help\n"
	       "  -c <config_file>  config file, see iosocks(8) for its syntax\n"
	       "");
}

static void signal_cb(EV_P_ ev_signal *w, int revents)
{
	assert((w->signum == SIGINT) || (w->signum == SIGTERM));
	ev_break(EV_A_ EVBREAK_ALL);
}

static void accept_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)mem_new(sizeof(conn_t));
	if (conn == NULL)
	{
		LOG("out of memory");
		return;
	}
	conn->sock_local = accept(w->fd, NULL, NULL);
	if (conn->sock_local < 0)
	{
		ERR("accept");
		mem_delete(conn);
		return;
	}
	setnonblock(conn->sock_local);
	settimeout(conn->sock_local);
	setkeepalive(conn->sock_local);
	conn->server_id = (int)(long)(w->data);
	ev_io_init(&conn->w_local_read, iosocks_recv_cb, conn->sock_local, EV_READ);
	conn->w_local_read.data = (void *)conn;
	ev_io_start(EV_A_ &conn->w_local_read);
}

static void iosocks_recv_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	ev_io_stop(EV_A_ w);

	conn->tx_bytes = recv(conn->sock_local, conn->tx_buf, BUF_SIZE, 0);
	if (conn->tx_bytes < 512)
	{
		if (conn->tx_bytes < 0)
		{
			LOG("client reset");
		}
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}

	// IoSocks Request
	// +-------+------+------+------+
	// | MAGIC | HOST | PORT |  IV  |
	// +-------+------+------+------+
	// |   4   | 257  |  15  | 236  |
	// +-------+------+------+------+
	uint8_t key[64];
	memcpy(conn->rx_buf, conn->tx_buf + 276, 236);
	memcpy(conn->rx_buf + 236, servers[conn->server_id].key, servers[conn->server_id].key_len);
	sha512(key, conn->rx_buf, 236 + servers[conn->server_id].key_len);
	enc_init(&conn->enc_evp, enc_rc4, key, 64);
	io_decrypt(conn->tx_buf, 276, &conn->enc_evp);
	if (ntohl(*((uint32_t *)(conn->tx_buf))) != MAGIC)
	{
		LOG("illegal client");
		close(conn->sock_local);
		mem_delete(conn);
		return;
	}
	char *host = (char *)conn->tx_buf + 4;
	char *port = (char *)conn->tx_buf + 261;
	host[256] = '\0';
	port[14] = '\0';
	LOG("connect %s:%s", host, port);
	conn->gai = (gai_t *)(conn->rx_buf);
	bzero(conn->gai, sizeof(gai_t));
	conn->gai->hints.ai_family = AF_UNSPEC;
	conn->gai->hints.ai_socktype = SOCK_STREAM;
	strcpy(conn->gai->host, host);
	strcpy(conn->gai->port, port);
	conn->gai->req.ar_name = conn->gai->host;
	conn->gai->req.ar_service = conn->gai->port;
	conn->gai->req.ar_request = &(conn->gai->hints);
	conn->gai->req.ar_result = NULL;
	conn->resolv_tried = 0;
	emit_resolv(conn);
}

static void emit_resolv(conn_t *conn)
{
	struct gaicb *req_ptr = &(conn->gai->req);
	struct sigevent sevp;
	sevp.sigev_notify = SIGEV_SIGNAL;
	sevp.sigev_signo = SIGIO;
	sevp.sigev_value.sival_ptr = (void *)conn;
	if (getaddrinfo_a(GAI_NOWAIT, &req_ptr, 1, &sevp) != 0)
	{
		ERR("getaddrinfo_a");
		close(conn->sock_local);
		mem_delete(conn);
	}
	conn->resolv_tried++;
}

static void resolv_cb(int signo, siginfo_t *info, void *context)
{
	conn_t *conn = (conn_t *)info->si_value.sival_ptr;

	assert(signo == SIGIO);
	assert(conn != NULL);

	if (gai_error(&conn->gai->req) == 0)
	{
		// 域名解析成功，建立远程连接
		conn->gai->res = conn->gai->req.ar_result;
		conn->sock_remote = socket(conn->gai->res->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (conn->sock_remote < 0)
		{
			ERR("socket");
			close(conn->sock_local);
			mem_delete(conn);
			return;
		}
		setnonblock(conn->sock_remote);
		settimeout(conn->sock_remote);
		setkeepalive(conn->sock_remote);
		ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
		conn->w_remote_write.data = (void *)conn;
		ev_io_start(EV_A_ &conn->w_remote_write);
		connect(conn->sock_remote, (struct sockaddr *)conn->gai->res->ai_addr, conn->gai->res->ai_addrlen);
	}
	else
	{
		// 域名解析失败
		if (conn->resolv_tried < MAX_TRY)
		{
			LOG("failed to resolv host: %s, try again", conn->gai->host);
			emit_resolv(conn);
		}
		else
		{
			LOG("failed to resolv host: %s, abort", conn->gai->host);
			close(conn->sock_local);
			mem_delete(conn);
		}
	}
}

static void connect_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	ev_io_stop(EV_A_ w);

	if (geterror(w->fd) == 0)
	{
		// 连接成功
		freeaddrinfo(conn->gai->req.ar_result);
		ev_io_init(&conn->w_local_read, local_read_cb, conn->sock_local, EV_READ);
		ev_io_init(&conn->w_local_write, local_write_cb, conn->sock_local, EV_WRITE);
		ev_io_init(&conn->w_remote_read, remote_read_cb, conn->sock_remote, EV_READ);
		ev_io_init(&conn->w_remote_write, remote_write_cb, conn->sock_remote, EV_WRITE);
		conn->w_local_read.data = (void *)conn;
		conn->w_local_write.data = (void *)conn;
		conn->w_remote_read.data = (void *)conn;
		conn->w_remote_write.data = (void *)conn;
		if (conn->tx_bytes > 512)
		{
			conn->tx_offset = 512;
			conn->tx_bytes -= 512;
			io_decrypt(conn->tx_buf + conn->tx_offset, conn->tx_bytes, &conn->enc_evp);
			ev_io_start(EV_A_ &conn->w_remote_write);
		}
		else
		{
			ev_io_start(EV_A_ &conn->w_local_read);
		}
		ev_io_start(EV_A_ &conn->w_remote_read);
	}
	else
	{
		// 连接失败
		close(conn->sock_remote);
		conn->gai->res = conn->gai->res->ai_next;
		if (conn->gai->res != NULL)
		{
			// 尝试连接下一个地址
			conn->sock_remote = socket(conn->gai->res->ai_family, SOCK_STREAM, IPPROTO_TCP);
			if (conn->sock_remote < 0)
			{
				ERR("socket");
				close(conn->sock_local);
				freeaddrinfo(conn->gai->req.ar_result);
				mem_delete(conn);
				return;
			}
			setnonblock(conn->sock_remote);
			settimeout(conn->sock_remote);
			setkeepalive(conn->sock_remote);
			ev_io_init(&conn->w_remote_write, connect_cb, conn->sock_remote, EV_WRITE);
			conn->w_remote_write.data = (void *)conn;
			ev_io_start(EV_A_ &conn->w_remote_write);
			connect(conn->sock_remote, (struct sockaddr *)conn->gai->res->ai_addr, conn->gai->res->ai_addrlen);
		}
		else
		{
			// 所有连接尝试均失败
			LOG("connect failed");
			close(conn->sock_local);
			freeaddrinfo(conn->gai->req.ar_result);
			mem_delete(conn);
		}
	}
}

static void local_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	conn->tx_bytes = recv(conn->sock_local, conn->tx_buf, BUF_SIZE, 0);
	if (conn->tx_bytes <= 0)
	{
		if (conn->tx_bytes < 0)
		{
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
	ev_io_stop(EV_A_ w);
	ev_io_start(EV_A_ &conn->w_remote_write);
}

static void local_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)w->data;

	assert(conn != NULL);
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
		ev_io_stop(EV_A_ w);
		ev_io_start(EV_A_ &conn->w_remote_read);
	}
}

static void remote_read_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);

	conn->rx_bytes = recv(conn->sock_remote, conn->rx_buf, BUF_SIZE, 0);
	if (conn->rx_bytes <= 0)
	{
		if (conn->rx_bytes < 0)
		{
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
	ev_io_stop(EV_A_ w);
	ev_io_start(EV_A_ &conn->w_local_write);
}

static void remote_write_cb(EV_P_ ev_io *w, int revents)
{
	conn_t *conn = (conn_t *)(w->data);

	assert(conn != NULL);
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
		ev_io_stop(EV_A_ w);
		ev_io_start(EV_A_ &conn->w_local_read);
	}
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
