# Don't edit Makefile! Use ../conf-* for configuration.

SHELL=/bin/sh

default: it

addcr: \
load addcr.o 
	./load addcr 

addcr.o: \
compile addcr.c 
	./compile addcr.c

argv0: \
load argv0.o 
	./load argv0 

argv0.o: \
compile argv0.c 
	./compile argv0.c

auto_home.c: \
auto-str home
	./auto-str auto_home `head -1 ../conf-home` > auto_home.c

auto_home.o: \
compile auto_home.c
	./compile auto_home.c

chkshsgr: \
load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: \
compile chkshsgr.c 
	./compile chkshsgr.c

choose: \
home warn-auto.sh choose.sh 
	rm -f choose
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> choose
	chmod 755 choose

commands.o: \
compile commands.c commands.h 
	./compile commands.c

compile: \
warn-auto.sh ../conf-cc
	( cat warn-auto.sh; \
	echo exec "`head -1 ../conf-cc`" '-c $${1+"$$@"}' \
	) > compile
	chmod 755 compile

date@: \
home warn-auto.sh date@.sh 
	rm -f date@
	cat warn-auto.sh date@.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> date@
	chmod 755 date@

delcr: \
load delcr.o 
	./load delcr 

delcr.o: \
compile delcr.c 
	./compile delcr.c

finger@: \
home warn-auto.sh finger@.sh 
	rm -f finger@
	cat warn-auto.sh finger@.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> finger@
	chmod 755 finger@

fixcrio: \
load fixcrio.o 
	./load fixcrio 

fixcrio.o: \
compile fixcrio.c 
	./compile fixcrio.c

fork.h: \
choose compile load tryvfork.c fork.h1 fork.h2
	./choose cl tryvfork fork.h1 fork.h2 > fork.h

hassgact.h: \
choose compile load trysgact.c hassgact.h1 hassgact.h2
	./choose cl trysgact hassgact.h1 hassgact.h2 > hassgact.h

hassgprm.h: \
choose compile load trysgprm.c hassgprm.h1 hassgprm.h2
	./choose cl trysgprm hassgprm.h1 hassgprm.h2 > hassgprm.h

hasshsgr.h: \
choose compile load tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

http@: \
home warn-auto.sh http@.sh 
	rm -f http@
	cat warn-auto.sh http@.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> http@
	chmod 755 http@

ip4_bit.o: \
compile ip4_bit.c ip_bit.h 
	./compile ip4_bit.c


it: it-base sysdeps

it-base: \
tcpserver tcprules tcprulescheck argv0 recordio tcpclient who@ date@ \
finger@ http@ tcpcat mconnect mconnect-io addcr delcr fixcrio rblsmtpd \
sysdeps

load: \
warn-auto.sh ../conf-ld
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo exec "`head -1 ../conf-ld`" \
	'-o "$$main" "$$main".o $${1+"$$@"} -ldnsresolv -lqlibs' \
	) > load
	chmod 755 load

mconnect: \
home warn-auto.sh mconnect.sh
	rm -f mconnect
	cat warn-auto.sh mconnect.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> mconnect
	chmod 755 mconnect

mconnect-io: \
load mconnect-io.o 
	./load mconnect-io 

mconnect-io.o: \
compile mconnect-io.c fork.h
	./compile mconnect-io.c

rblsmtpd: \
load rblsmtpd.o commands.o socket.lib
	./load rblsmtpd commands.o `cat socket.lib`

rblsmtpd.o: \
compile rblsmtpd.c 
	./compile rblsmtpd.c

readclose.o: \
compile readclose.c 
	./compile readclose.c

recordio: \
load recordio.o 
	./load recordio 

recordio.o: \
compile recordio.c 
	./compile recordio.c

remoteinfo.o: \
compile remoteinfo.c remoteinfo.h 
	./compile remoteinfo.c 

rules.o: \
compile rules.c ip4_bit.c ip6_bit.c ip_bit.h 
	./compile rules.c ip4_bit.c ip6_bit.c

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

sysdeps: systype compile load hassgact.h hassgprm.h hasshsgr.h 
	rm -f sysdeps
	cat systype compile load >> sysdeps
	grep sysdep hassgact.h >> sysdeps
	grep sysdep hassgprm.h >> sysdeps
	grep sysdep hasshsgr.h >> sysdeps

systype: \
find-systype.sh ../conf-cc ../conf-ld trycpp.c x86cpuid.c
	( cat warn-auto.sh; \
	echo CC=\'`head -1 ../conf-cc`\'; \
	echo LD=\'`head -1 ../conf-ld`\'; \
	cat find-systype.sh; \
	) | sh > systype

tcpcat: \
home warn-auto.sh tcpcat.sh home
	rm -f tcpcat
	cat warn-auto.sh tcpcat.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> tcpcat
	chmod 755 tcpcat

tcpclient: \
load tcpclient.o remoteinfo.o
	./load tcpclient remoteinfo.o `cat socket.lib`

tcpclient.o: \
compile tcpclient.c remoteinfo.h
	./compile tcpclient.c 

tcprules: \
load tcprules.o ip4_bit.o
	./load tcprules ip4_bit.o ip6_bit.o

tcprules.o: \
compile tcprules.c 
	./compile tcprules.c

tcprulescheck: \
load tcprulescheck.o 
	./load tcprulescheck rules.o ip4_bit.o ip6_bit.o

tcprulescheck.o: \
compile tcprulescheck.c 
	./compile tcprulescheck.c 

tcpserver: \
load tcpserver.o remoteinfo.o rules.o ip4_bit.o ip6_bit.o socket.lib 
	./load tcpserver rules.o remoteinfo.o ip4_bit.o ip6_bit.o \
	`cat socket.lib`

tcpserver.o: \
compile tcpserver.c remoteinfo.c remoteinfo.h fork.h
	./compile tcpserver.c remoteinfo.h 

who@: \
home warn-auto.sh who@.sh 
	rm -f who@
	cat warn-auto.sh who@.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> who@
	chmod 755 who@

clean: 
	rm -f `cat TARGETS`
