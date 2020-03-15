# Don't edit Makefile! Use ../conf-* for configuration.

SHELL=/bin/sh

default: one five

addcr.0: \
addcr.1
	nroff -man addcr.1 > addcr.0

argv0.0: \
argv0.1
	nroff -man argv0.1 > argv0.0

clean: \
TARGETS
	rm -f `cat TARGETS`

date@.0: \
date@.1
	nroff -man date@.1 > date@.0

delcr.0: \
delcr.1
	nroff -man delcr.1 > delcr.0

finger@.0: \
finger@.1
	nroff -man finger@.1 > finger@.0

fixcrio.0: \
fixcrio.1
	nroff -man fixcrio.1 > fixcrio.0

http@.0: \
http@.1
	nroff -man http@.1 > http@.0

mconnect.0: \
mconnect.1
	nroff -man mconnect.1 > mconnect.0

rblsmtpd.0: \
rblsmtpd.1
	nroff -man rblsmtpd.1 > rblsmtpd.0

recordio.0: \
recordio.1
	nroff -man recordio.1 > recordio.0

tcp-environ.0: \
tcp-environ.5
	nroff -man tcp-environ.5 > tcp-environ.0

tcpcat.0: \
tcpcat.1
	nroff -man tcpcat.1 > tcpcat.0

tcpclient.0: \
tcpclient.1
	nroff -man tcpclient.1 > tcpclient.0

tcprules.0: \
tcprules.1
	nroff -man tcprules.1 > tcprules.0

tcprulescheck.0: \
tcprulescheck.1
	nroff -man tcprulescheck.1 > tcprulescheck.0

tcpserver.0: \
tcpserver.1
	nroff -man tcpserver.1 > tcpserver.0

who@.0: \
who@.1
	nroff -man who@.1 > who@.0

one: \
addcr.0 argv0.0 date@.0 delcr.0 finger@.0 fixcrio.0 \
http@.0 mconnect.0 rblsmtpd.0 recordio.0 tcpcat.0 \
tcpclient.0 tcprules.0 tcprulescheck.0 tcpserver.0 who@.0

five: \
tcp-environ.0
