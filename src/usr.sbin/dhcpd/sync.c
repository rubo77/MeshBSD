/*	$OpenBSD: sync.c,v 1.16 2015/01/16 06:40:16 deraadt Exp $	*/

/*
 * Copyright (c) 2008 Bob Beck <beck@openbsd.org>
 * Copyright (c) 2006, 2007 Reyk Floeter <reyk@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 * Copyright (c) 2016 Henning Matyschok
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/stdint.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha.h>

#include <netdb.h>

#include <openssl/hmac.h>

#include "dhcpd.h"
#include "sync.h"

LIST_HEAD(synchosts, sync_host) sync_hosts = LIST_HEAD_INITIALIZER(sync_hosts);

u_int32_t sync_counter;

int sync_debug;
int syncfd = -1;
int sendmcast;

struct sockaddr_in sync_in;
struct sockaddr_in sync_out;

static char *sync_key = NULL;

int
sync_addhost(const char *name, u_short port)
{
	struct addrinfo hints, *res, *res0;
	struct sync_host *shost;
	struct sockaddr_in *addr = NULL;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(name, NULL, &hints, &res0) != 0)
		return (EINVAL);
	for (res = res0; res != NULL; res = res->ai_next) {
		if (addr == NULL && res->ai_family == AF_INET) {
			addr = (void *)res->ai_addr;
			break;
		}
	}
	if (addr == NULL) {
		freeaddrinfo(res0);
		return (EINVAL);
	}
	if ((shost = (struct sync_host *)
	    calloc(1, sizeof(struct sync_host))) == NULL) {
		freeaddrinfo(res0);
		return (ENOMEM);
	}
	shost->h_name = strdup(name);
	if (shost->h_name == NULL) {
		free(shost);
		freeaddrinfo(res0);
		return (ENOMEM);
	}

	shost->sh_addr.sin_family = AF_INET;
	shost->sh_addr.sin_port = htons(port);
	shost->sh_addr.sin_addr.s_addr = addr->sin_addr.s_addr;
	
	freeaddrinfo(res0);

	LIST_INSERT_HEAD(&sync_hosts, shost, h_entry);

	if (sync_debug) {
		(void)note("added dhcp sync host %s "
			"(address %s, port %d)\n",
		    shost->h_name, 
		    inet_ntoa(shost->sh_addr.sin_addr), 
		    port);
	}
	return (0);
}

int
sync_init(const char *iface, const char *baddr, u_short port)
{
	int one = 1;
	u_int8_t ttl;
	struct ifreq ifr;
	struct ip_mreq mreq;
	struct sockaddr_in *addr;
	char ifnam[IFNAMSIZ], *ttlstr;
	const char *errstr;
	struct in_addr ina;

	if (iface != NULL)
		sendmcast++;

	if (sync_key) {
		free(sync_key);
		sync_key = NULL;
	}
	
	bzero(&ina, sizeof(ina));
	if (baddr != NULL) {
		if (inet_pton(AF_INET, baddr, &ina) != 1) {
			ina.s_addr = htonl(INADDR_ANY);
			if (iface == NULL)
				iface = baddr;
			else if (iface != NULL 
				&& strcmp(baddr, iface) != 0) {
				(void)fprintf(stderr, "multicast "
					"interface does "
				    "not match");
				goto fail;
			}
		}
	}
/*
 * XXX; probably a memory leak.
 */
	sync_key = SHA1_File(DHCP_SYNC_KEY, NULL);
	if (sync_key == NULL) {
		if (errno != ENOENT) {
			fprintf(stderr, "failed to open sync key: %s\n",
			    strerror(errno));
			goto fail;
		}
		/* Use empty key by default */
		sync_key = strdup("");
	} else
		sync_key = strdup(sync_key);
	
	syncfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (syncfd == -1) 
		goto fail1;

	if (setsockopt(syncfd, SOL_SOCKET, SO_REUSEADDR, &one,
	    sizeof(one)) == -1)
		goto fail2;

	bzero(&sync_out, sizeof(sync_out));
	sync_out.sin_family = AF_INET;
	sync_out.sin_len = sizeof(sync_out);
	sync_out.sin_addr.s_addr = ina.s_addr;
	if (baddr == NULL && iface == NULL)
		sync_out.sin_port = 0;
	else
		sync_out.sin_port = htons(port);

	if (bind(syncfd, (struct sockaddr *)&sync_out, sizeof(sync_out)) == -1)
		goto fail2;

	/* Don't use multicast messages */
	if (iface == NULL)
		goto out;

	(void)strlcpy(ifnam, iface, sizeof(ifnam));
	
	ttl = DHCP_SYNC_MCASTTTL;
	if ((ttlstr = strchr(ifnam, ':')) != NULL) {
		*ttlstr++ = '\0';
		ttl = (u_int8_t)strtonum(ttlstr, 1, UINT8_MAX, &errstr);
		if (errstr) {
			(void)fprintf(stderr, "invalid "
				"multicast ttl %s: %s",
			    ttlstr, errstr);
			goto fail2;
		}
	}

	bzero(&ifr, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifnam, sizeof(ifr.ifr_name));
	if (ioctl(syncfd, SIOCGIFADDR, &ifr) == -1)
		goto fail2;

	bzero(&sync_in, sizeof(sync_in));
	addr = (void *)&ifr.ifr_addr;
	sync_in.sin_family = AF_INET;
	sync_in.sin_len = sizeof(sync_in);
	sync_in.sin_addr.s_addr = addr->sin_addr.s_addr;
	sync_in.sin_port = htons(port);

	bzero(&mreq, sizeof(mreq));
	sync_out.sin_addr.s_addr = inet_addr(DHCP_SYNC_MCASTADDR);
	mreq.imr_multiaddr.s_addr = inet_addr(DHCP_SYNC_MCASTADDR);
	mreq.imr_interface.s_addr = sync_in.sin_addr.s_addr;

	if (setsockopt(syncfd, IPPROTO_IP,
	    IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
		(void)fprintf(stderr, "failed to add multicast "
			"membership to %s: %s",
		    DHCP_SYNC_MCASTADDR, 
		    strerror(errno));
		goto fail2;
	}
	if (setsockopt(syncfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
	    sizeof(ttl)) == -1) {
		(void)fprintf(stderr, "failed to set "
			"multicast ttl to %u: %s\n", ttl, 
				strerror(errno));
		(void)setsockopt(syncfd, IPPROTO_IP,
		    IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
		goto fail2;
	}

	if (sync_debug) {
		syslog(LOG_DEBUG, "using multicast dhcp sync %smode "
			"(ttl %u, group %s, port %d)\n",
			sendmcast ? "" : "receive ",
			ttl, inet_ntoa(sync_out.sin_addr), port);
	}
out:
	return (syncfd);
fail2:
	(void)close(syncfd);
fail1:
	free(sync_key);
	sync_key = NULL;
fail:
	syncfd = -1;
	goto out;
}

void
sync_recv(void)
{
	struct dhcp_synchdr *hdr;
	struct sockaddr_in addr;
	struct dhcp_synctlv_hdr *tlv;
	struct dhcp_synctlv_lease *lv;
	struct lease	*lease;
	u_int8_t buf[DHCP_SYNC_MAXSIZE];
	u_int8_t hmac[2][DHCP_SYNC_HMAC_LEN];
	struct lease l, *lp;
	u_int8_t *p;
	socklen_t addr_len;
	ssize_t status;
	size_t len;
	u_int hmac_len;

	bzero(&addr, sizeof(addr));
	bzero(buf, sizeof(buf));

	addr_len = sizeof(addr);
	if ((status = recvfrom(syncfd, buf, sizeof(buf), 0,
	    (struct sockaddr *)&addr, &addr_len)) < 1)
		return;
	
	len = status;
	
	if (addr.sin_addr.s_addr != htonl(INADDR_ANY) &&
	    bcmp(&sync_in.sin_addr, &addr.sin_addr,
	    sizeof(addr.sin_addr)) == 0)
		return;

	/* Ignore invalid or truncated packets */
	hdr = (struct dhcp_synchdr *)buf;
	if (len < sizeof(struct dhcp_synchdr) ||
	    hdr->sh_version != DHCP_SYNC_VERSION ||
	    hdr->sh_af != AF_INET ||
	    len < ntohs(hdr->sh_length))
		goto trunc;
	len = ntohs(hdr->sh_length);

	/* Compute and validate HMAC */
	(void)memcpy(hmac[0], hdr->sh_hmac, DHCP_SYNC_HMAC_LEN);
	bzero(hdr->sh_hmac, DHCP_SYNC_HMAC_LEN);
	HMAC(EVP_sha1(), sync_key, strlen(sync_key), buf, len,
	    hmac[1], &hmac_len);
	if (bcmp(hmac[0], hmac[1], DHCP_SYNC_HMAC_LEN) != 0)
		goto trunc;

	if (sync_debug)
		note("%s(sync): received packet of %d bytes\n",
		    inet_ntoa(addr.sin_addr), (int)len);

	p = (u_int8_t *)(hdr + 1);
	while (len) {
		tlv = (struct dhcp_synctlv_hdr *)p;

		if (len < sizeof(struct dhcp_synctlv_hdr) ||
		    len < ntohs(tlv->st_length))
			goto trunc;

		switch (ntohs(tlv->st_type)) {
		case DHCP_SYNC_LEASE:
			lv = (struct dhcp_synctlv_lease *)tlv;
			if (sizeof(*lv) > ntohs(tlv->st_length))
				goto trunc;
			lease = find_lease_by_hw_addr(
			    lv->lv_hardware_addr.haddr,
			    lv->lv_hardware_addr.hlen);
			if (lease == NULL)
				lease = find_lease_by_ip_addr(lv->lv_ip_addr);

			lp = &l;
			
			(void)memset(lp, 0, sizeof(*lp));
			
			lp->timestamp = ntohl(lv->lv_timestamp);
			lp->starts = ntohl(lv->lv_starts);
			lp->ends = ntohl(lv->lv_ends);
			
			(void)memcpy(&lp->ip_addr, &lv->lv_ip_addr,
			    sizeof(lp->ip_addr));
			(void)memcpy(&lp->hardware_addr, &lv->lv_hardware_addr,
			    sizeof(lp->hardware_addr));
			(void)note("DHCP_SYNC_LEASE from %s for hw %s -> ip %s, "
			    "start %lld, end %lld",
			    inet_ntoa(addr.sin_addr),
			    print_hw_addr(lp->hardware_addr.htype,
			    lp->hardware_addr.hlen, lp->hardware_addr.haddr),
			    piaddr(lp->ip_addr),
			    (long long)lp->starts, (long long)lp->ends);
			
			/* now whack the lease in there */
			
			if (lease == NULL) {
				enter_lease(lp);
				write_leases();
			} else if (lease->ends < lp->ends)
				(void)supersede_lease(lease, lp, 1);
			else if (lease->ends > lp->ends)
				/*
				 * our partner sent us a lease
				 * that is older than what we have,
				 * so re-educate them with what we
				 * know is newer.
				 */
				sync_lease(lease);
			break;
		case DHCP_SYNC_END:
			goto done;
		default:
			printf("invalid type: %d\n", ntohs(tlv->st_type));
			goto trunc;
		}
		len -= ntohs(tlv->st_length);
		p = ((u_int8_t *)tlv) + ntohs(tlv->st_length);
	}
done:
	return;
trunc:
	if (sync_debug)
		note("%s(sync): truncated or invalid packet\n",
		    inet_ntoa(addr.sin_addr));
}

void
sync_send(struct iovec *iov, int iovlen)
{
	struct sync_host *shost;
	struct msghdr msg;
	
	if (syncfd == -1)
		return;

	/* setup buffer */
	bzero(&msg, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	if (sendmcast) {
		if (sync_debug)
			note("sending multicast sync message\n");
		msg.msg_name = &sync_out;
		msg.msg_namelen = sizeof(sync_out);
		if (sendmsg(syncfd, &msg, 0) == -1)
			warning("sending multicast sync message failed: %m");
	}

	LIST_FOREACH(shost, &sync_hosts, h_entry) {
		if (sync_debug)
			note("sending sync message to %s (%s)\n",
			    shost->h_name, inet_ntoa(shost->sh_addr.sin_addr));
		msg.msg_name = &shost->sh_addr;
		msg.msg_namelen = sizeof(shost->sh_addr);
		if (sendmsg(syncfd, &msg, 0) == -1)
			warning("sending sync message failed: %m");
	}
}

void
sync_lease(struct lease *lease)
{
	struct iovec iov[4];
	struct dhcp_synchdr hdr;
	struct dhcp_synctlv_lease lv;
	struct dhcp_synctlv_hdr end;
	char pad[DHCP_ALIGNBYTES];
	u_int16_t leaselen, padlen;
	int i = 0;
	HMAC_CTX ctx;
	u_int hmac_len;

	if (sync_key == NULL)
		return;

	bzero(&hdr, sizeof(hdr));
	bzero(&lv, sizeof(lv));
	bzero(&pad, sizeof(pad));

	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, sync_key, strlen(sync_key), EVP_sha1());

	leaselen = sizeof(lv);
	padlen = DHCP_ALIGN(leaselen) - leaselen;

	/* Add DHCP sync packet header */
	hdr.sh_version = DHCP_SYNC_VERSION;
	hdr.sh_af = AF_INET;
	hdr.sh_counter = sync_counter++;
	hdr.sh_length = htons(sizeof(hdr) + sizeof(lv) + padlen + sizeof(end));
	iov[i].iov_base = &hdr;
	iov[i].iov_len = sizeof(hdr);
	HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
	i++;

	/* Add single DHCP sync address entry */
	lv.lv_type = htons(DHCP_SYNC_LEASE);
	lv.lv_length = htons(leaselen + padlen);
	lv.lv_timestamp = htonl(lease->timestamp);
	lv.lv_starts = htonl(lease->starts);
	lv.lv_ends =  htonl(lease->ends);
	
	(void)memcpy(&lv.lv_ip_addr, &lease->ip_addr, 
		sizeof(lv.lv_ip_addr));
	(void)memcpy(&lv.lv_hardware_addr, &lease->hardware_addr,
	    sizeof(lv.lv_hardware_addr));
	(void)note("sending DHCP_SYNC_LEASE for "
		"hw %s -> ip %s, start %d, end %d",
	    print_hw_addr(lv.lv_hardware_addr.htype, 
	    lv.lv_hardware_addr.hlen,
	    lv.lv_hardware_addr.haddr), 
	    piaddr(lease->ip_addr),
	    ntohl(lv.lv_starts), 
	    ntohl(lv.lv_ends));
	    
	iov[i].iov_base = &lv;
	iov[i].iov_len = sizeof(lv);
	HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
	i++;

	iov[i].iov_base = pad;
	iov[i].iov_len = padlen;
	HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
	i++;

	/* Add end marker */
	end.st_type = htons(DHCP_SYNC_END);
	end.st_length = htons(sizeof(end));
	iov[i].iov_base = &end;
	iov[i].iov_len = sizeof(end);
	HMAC_Update(&ctx, iov[i].iov_base, iov[i].iov_len);
	i++;

	HMAC_Final(&ctx, hdr.sh_hmac, &hmac_len);

	/* Send message to the target hosts */
	sync_send(iov, i);
	HMAC_CTX_cleanup(&ctx);
}
