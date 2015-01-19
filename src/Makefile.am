AM_CFLAGS=-pipe -W -Wall -Wno-unused-parameter -fno-strict-aliasing -D_GNU_SOURCE

bin_PROGRAMS = ioserver ioclient iodns ioredir

ioserver_SOURCES = conf.c \
                   encrypt.c \
                   log.c \
                   mem.c \
                   ioserver.c \
                   rc4.c \
                   sha512.c \
                   utils.c \
                   conf.h \
                   encrypt.h \
                   log.h \
                   mem.h \
                   rc4.h \
                   sha512.h \
                   utils.h
ioserver_LDADD = $(EV_LIBS) $(ANL_LIBS)

ioclient_SOURCES = conf.c \
                   encrypt.c \
                   ioclient.c \
                   log.c \
                   mem.c \
                   rc4.c \
                   sha512.c \
                   utils.c \
                   conf.h \
                   encrypt.h \
                   log.h \
                   mem.h \
                   rc4.h \
                   sha512.h \
                   utils.h
ioclient_LDADD = $(EV_LIBS)

iodns_SOURCES = conf.c \
                encrypt.c \
                iodns.c \
                log.c \
                mem.c \
                rc4.c \
                sha512.c \
                utils.c \
                conf.h \
                encrypt.h \
                log.h \
                mem.h \
                rc4.h \
                sha512.h \
                utils.h
iodns_LDADD = $(EV_LIBS) $(RESOLV_LIBS)

ioredir_SOURCES = conf.c \
                  encrypt.c \
                  ioredir.c \
                  log.c \
                  mem.c \
                  rc4.c \
                  sha512.c \
                  utils.c \
                  conf.h \
                  encrypt.h \
                  log.h \
                  mem.h \
                  rc4.h \
                  sha512.h \
                  utils.h
ioredir_LDADD = $(EV_LIBS)
