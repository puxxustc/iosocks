AM_CFLAGS=-pipe -W -Wall -fno-strict-aliasing -D_GNU_SOURCE

bin_PROGRAMS = ioserver ioclient ioredir

EXTRA_ioserver_SOURCES = ev.c ev.h ev_vars.h ev_wrap.h ev_epoll.c ev_select.c ev_poll.c ev_kqueue.c ev_port.c ev_win32.c

ioserver_SOURCES = \
    async_connect.c async_resolv.c conf.c crypto.c log.c md5.c relay.c utils.c ioserver.c \
    async_connect.h async_resolv.h conf.h crypto.h log.h md5.h relay.h utils.h
ioserver_LDADD = $(LIB_ANL)

ioclient_SOURCES = \
    async_connect.c conf.c crypto.c log.c md5.c relay.c socks5.c utils.c ioclient.c \
    async_connect.h conf.h crypto.h log.h md5.h relay.h socks5.h utils.h
ioclient_LDADD = 

ioredir_SOURCES = \
    async_connect.c conf.c crypto.c log.c md5.c relay.c socks5.c utils.c ioredir.c \
    async_connect.h conf.h crypto.h log.h md5.h relay.h socks5.h utils.h
ioredir_LDADD = 

if BUILD_EV
ioserver_SOURCES += ev.c ev.h
ioclient_SOURCES += ev.c ev.h
ioredir_SOURCES += ev.c ev.h
else
ioserver_LDADD += $(LIB_EV)
ioclient_LDADD += $(LIB_EV)
ioredir_LDADD += $(LIB_EV)
endif