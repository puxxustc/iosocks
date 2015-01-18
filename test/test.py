#!/usr/bin/env python3

import sys
import os
import signal
import time
from subprocess import Popen

ioserver = ['src/ioserver', '-c', 'test/test.conf']
ioclient = ['src/ioclient', '-c', 'test/test.conf']
iodns = ['src/iodns', '-c', 'test/test.conf']

p1 = Popen(ioserver, shell=False, bufsize=0, close_fds=True)
p2 = Popen(ioclient, shell=False, bufsize=0, close_fds=True)
p3 = Popen(iodns, shell=False, bufsize=0, close_fds=True)

time.sleep(1)

cmds = ['curl --socks5-hostname 127.0.0.2:1080 https://twitter.com/',
        'curl --socks5-hostname 127.0.0.2:1080 https://github.com/',
        'curl --socks5-hostname 127.0.0.2:1080 https://www.facebook.com/',
        'curl --socks5-hostname 127.0.0.2:1080 https://www.youtube.com/',
        'dig @127.0.0.1 -p 5300 twitter.com',
        'dig @127.0.0.1 -p 5300 github.com',
        'dig @127.0.0.1 -p 5300 www.facebook.com',
        'dig @127.0.0.1 -p 5300 www.youtube.com',
        'dig @127.0.0.1 -p 5300 twitter.com',
        'dig @127.0.0.1 -p 5300 +tcp twitter.com',
        'dig @127.0.0.1 -p 5300 +tcp github.com',
        'dig @127.0.0.1 -p 5300 +tcp www.facebook.com',
        'dig @127.0.0.1 -p 5300 +tcp www.youtube.com',
        'dig @127.0.0.1 -p 5300 +tcp twitter.com']

for cmd in cmds:
	p4 = Popen(cmd.split(), shell=False, bufsize=0, close_fds=True)

	if p4 is not None:
		r = p4.wait()
	if r == 0:
		print('test passed')

for p in [p1]:
	try:
		os.kill(p.pid, signal.SIGINT)
		os.waitpid(p.pid, 0)
	except OSError:
		pass

for p in [p2]:
	try:
		os.kill(p.pid, signal.SIGINT)
		os.waitpid(p.pid, 0)
	except OSError:
		pass

for p in [p3]:
	try:
		os.kill(p.pid, signal.SIGINT)
		os.waitpid(p.pid, 0)
	except OSError:
		pass

sys.exit(r)
