AM_CFLAGS=-pipe -W -Wall -fno-strict-aliasing -D_GNU_SOURCE

bin_PROGRAMS = ioserver ioclient ioredir

EXTRA_ioserver_SOURCES = ev.c ev.h ev_vars.h ev_wrap.h ev_epoll.c ev_select.c ev_poll.c ev_kqueue.c ev_port.c ev_win32.c

ioserver_SOURCES = \
    conf.c encrypt.c ioserver.c log.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h rc4.h sha512.h utils.h
ioserver_LDADD = $(LIB_ANL)

ioclient_SOURCES = \
    conf.c encrypt.c ioclient.c log.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h rc4.h sha512.h utils.h
ioclient_LDADD = 

ioredir_SOURCES = \
    conf.c encrypt.c ioredir.c log.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h rc4.h sha512.h utils.h
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