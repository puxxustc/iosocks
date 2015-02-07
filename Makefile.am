SUBDIRS = src

EXTRA_DIST = man/iosocks.8 contrib/systemd/ioserver@.service \
             contrib/systemd/ioclient@.service \
             contrib/systemd/iodns@.service \
             contrib/systemd/ioredir@.service

man_MANS = man/iosocks.8

systemddir=$(libdir)/systemd/system
systemd_DATA=contrib/systemd/ioserver@.service \
             contrib/systemd/ioclient@.service \
             contrib/systemd/iodns@.service \
             contrib/systemd/ioredir@.service
