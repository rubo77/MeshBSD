# $OpenBSD: Makefile,v 1.5 2014/07/11 09:42:27 yasuoka Exp $

SRCS=	bootp.c confpars.c db.c dhcp.c dhcpd.c bpf.c packet.c errwarn.c \
	dispatch.c print.c memory.c options.c inet.c conflex.c parse.c \
	alloc.c tables.c tree.c hash.c convert.c icmp.c pfutils.c sync.c \
	udpsock.c
PROG=	dhcpd
MAN=	dhcpd.8 dhcpd.conf.5 dhcpd.leases.5 dhcp-options.5

LIBADD=	crypto md

.include <bsd.prog.mk>
