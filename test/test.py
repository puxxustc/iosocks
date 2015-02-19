#!/usr/bin/env python3

import sys
import os
import signal
import time
from subprocess import Popen

ioserver = ['src/ioserver', '-c', 'test/test.conf']
ioclient = ['src/ioclient', '-c', 'test/test.conf']
ioredir =  ['src/ioredir',  '-c', 'test/test.conf']

p1 = Popen(ioserver, shell=False, bufsize=0, close_fds=True)
p2 = Popen(ioclient, shell=False, bufsize=0, close_fds=True)
p3 = Popen(ioredir,  shell=False, bufsize=0, close_fds=True)
time.sleep(1)

cmds = ['curl -o /dev/null --socks5-hostname 127.0.0.2:1080 https://github.com/',
        'curl -o /dev/null --socks5-hostname 127.0.0.2:1080 https://www.baidu.com/',
        'curl -o /dev/null --socks5 127.0.0.2:1080 https://github.com/',
        'curl -o /dev/null --local-port 2001 https://github.com/',
        'curl -o /dev/null --local-port 2002 https://www.baidu.com/']

for cmd in cmds:
	p4 = Popen(cmd.split(), shell=False, bufsize=0, close_fds=True)
	if p4 is not None:
		r = p4.wait()
	if r == 0:
		print('test passed')
	time.sleep(1)

for p in [p1, p2, p3]:
	try:
		os.kill(p.pid, signal.SIGINT)
		os.waitpid(p.pid, 0)
	except OSError:
		pass

sys.exit(r)
