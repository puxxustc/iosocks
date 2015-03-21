AM_CFLAGS=-pipe -W -Wall -fno-strict-aliasing -D_GNU_SOURCE

bin_PROGRAMS = ioserver ioclient ioredir

ioserver_SOURCES = \
    conf.c encrypt.c ioserver.c log.c mem.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h mem.h rc4.h sha512.h utils.h
ioserver_LDADD = $(LIB_EV) $(LIB_ANL)

ioclient_SOURCES = \
    conf.c encrypt.c ioclient.c log.c mem.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h mem.h rc4.h sha512.h utils.h
ioclient_LDADD = $(LIB_EV)

ioredir_SOURCES = \
    conf.c encrypt.c ioredir.c log.c mem.c rc4.c sha512.c utils.c \
    conf.h encrypt.h log.h mem.h rc4.h sha512.h utils.h
ioredir_LDADD = $(LIB_EV)
