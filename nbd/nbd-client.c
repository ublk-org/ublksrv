// SPDX-License-Identifier: GPL-2.0

/*
 * Open connection for network block device
 *
 * Copyright 1997,1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
 * Copyright (c) 2002 - 2011 Wouter Verhelst <w@uter.be>
 *
 * Version 1.0 - 64bit issues should be fixed, now
 * Version 1.1 - added bs (blocksize) option (Alexey Guzeev, aga@permonline.ru)
 * Version 1.2 - I added new option '-d' to send the disconnect request
 * Version 2.0 - Version synchronised with server
 * Version 2.1 - Check for disconnection before INIT_PASSWD is received
 * 	to make errormsg a bit more helpful in case the server can't
 * 	open the exported file.
 * 16/03/2010 - Add IPv6 support.
 * 	Kitt Tientanopajai <kitt@kitty.in.th>
 *	Neutron Soutmun <neo.neutron@gmail.com>
 *	Suriya Soutmun <darksolar@gmail.com>
 */

#include <config.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include <linux/ioctl.h>

#define MY_NAME "ublk_nbd"
#include "cliserv.h"

#if HAVE_GNUTLS && !defined(NOTLS)
#include "crypto-gnutls.h"
#endif

#define NBDC_DO_LIST 1

int opennet(const char *name, const char* portstr, int sdp) {
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	int e;

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(name, portstr, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		return -1;
	}

	if(sdp) {
#ifdef WITH_SDP
		if (ai->ai_family == AF_INET)
			ai->ai_family = AF_INET_SDP;
		else (ai->ai_family == AF_INET6)
			ai->ai_family = AF_INET6_SDP;
#else
		err("Can't do SDP: I was not compiled with SDP support!");
#endif
	}

	for(rp = ai; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sock == -1)
			continue;	/* error */

		if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* success */
			
		close(sock);
	}

	if (rp == NULL) {
		err_nonfatal("Socket failed: %m");
		sock = -1;
		goto err;
	}

	setmysockopt(sock);
err:
	freeaddrinfo(ai);
	return sock;
}

int openunix(const char *path) {
	int sock;
	struct sockaddr_un un_addr;
	memset(&un_addr, 0, sizeof(un_addr));

	un_addr.sun_family = AF_UNIX;
	if (strnlen(path, sizeof(un_addr.sun_path)) == sizeof(un_addr.sun_path)) {
		err_nonfatal("UNIX socket path too long");
		return -1;
	}

	strncpy(un_addr.sun_path, path, sizeof(un_addr.sun_path) - 1);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		err_nonfatal("SOCKET failed");
		return -1;
	};

	if (connect(sock, &un_addr, sizeof(un_addr)) == -1) {
		err_nonfatal("CONNECT failed");
		close(sock);
		return -1;
	}
	return sock;
}

static void send_request(int sock, uint32_t opt, ssize_t datasize, void* data) {
	struct {
		uint64_t magic;
		uint32_t opt;
		uint32_t datasize;
	} __attribute__((packed)) header = {
		ntohll(opts_magic),
		ntohl(opt),
		ntohl(datasize),
	};
	if(datasize < 0) {
		datasize = strlen((char*)data);
		header.datasize = htonl(datasize);
	}
	writeit(sock, &header, sizeof(header));
	if(data != NULL) {
		writeit(sock, data, datasize);
	}
}

static void send_info_request(int sock, uint32_t opt, int n_reqs,
		uint16_t* reqs, char* name) {
	uint16_t rlen = htons(n_reqs);
	uint32_t nlen = htonl(strlen(name));

	send_request(sock, opt, sizeof(uint32_t) + strlen(name) + sizeof(uint16_t) + n_reqs * sizeof(uint16_t), NULL);
	writeit(sock, &nlen, sizeof(nlen));
	writeit(sock, name, strlen(name));
	writeit(sock, &rlen, sizeof(rlen));
	if(n_reqs > 0) {
		writeit(sock, reqs, n_reqs * sizeof(uint16_t));
	}
}

struct reply {
	uint64_t magic;
	uint32_t opt;
	uint32_t reply_type;
	uint32_t datasize;
	char data[];
} __attribute__((packed));

static struct reply* read_reply(int sock) {
	struct reply *retval = (struct reply *)malloc(sizeof(struct reply));
	readit(sock, retval, sizeof(*retval));
	retval->magic = ntohll(retval->magic);
	retval->opt = ntohl(retval->opt);
	retval->reply_type = ntohl(retval->reply_type);
	retval->datasize = ntohl(retval->datasize);
	if (retval->magic != rep_magic) {
		fprintf(stderr, "E: received invalid negotiation magic %" PRIu64 " (expected %" PRIu64 ")", retval->magic, rep_magic);
		exit(EXIT_FAILURE);
	}
	if (retval->datasize > 0) {
		retval = (struct reply *)realloc(retval, sizeof(struct reply) + retval->datasize);
		readit(sock, &(retval->data), retval->datasize);
	}
	return retval;
}

static void ask_list(int sock) {
	uint32_t opt_server;
	uint32_t len;
	uint32_t lenn;
	uint32_t reptype;
	uint64_t magic;
	int rlen;
#define BUF_SIZE 1024
	char buf[BUF_SIZE];

	send_request(sock, NBD_OPT_LIST, 0, NULL);
	/* newline, move away from the "Negotiation:" line */
	printf("\n");
	do {
		memset(buf, 0, 1024);
		if(read(sock, &magic, sizeof(magic)) < 0) {
			err("Reading magic from server: %m");
		}
		if(read(sock, &opt_server, sizeof(opt_server)) < 0) {
			err("Reading option: %m");
		}
		if(read(sock, &reptype, sizeof(reptype)) <0) {
			err("Reading reply from server: %m");
		}
		if(read(sock, &len, sizeof(len)) < 0) {
			err("Reading length from server: %m");
		}
		magic=ntohll(magic);
		len=ntohl(len);
		reptype=ntohl(reptype);
		if(magic != rep_magic) {
			err("Not enough magic from server");
		}
		if(reptype & NBD_REP_FLAG_ERROR) {
			switch(reptype) {
				case NBD_REP_ERR_POLICY:
					fprintf(stderr, "\nE: listing not allowed by server.\n");
					break;
				default:
					fprintf(stderr, "\nE: unexpected error from server.\n");
					break;
			}
			if(len > 0 && len < BUF_SIZE) {
				if((rlen=read(sock, buf, len)) < 0) {
					fprintf(stderr, "\nE: could not read error message from server\n");
				} else {
					buf[rlen] = '\0';
					fprintf(stderr, "Server said: %s\n", buf);
				}
			}
			exit(EXIT_FAILURE);
		} else {
			if(reptype != NBD_REP_ACK) {
				if(reptype != NBD_REP_SERVER) {
					err("Server sent us a reply we don't understand!");
				}
				if(read(sock, &lenn, sizeof(lenn)) < 0) {
					fprintf(stderr, "\nE: could not read export name length from server\n");
					exit(EXIT_FAILURE);
				}
				lenn=ntohl(lenn);
				if (lenn >= BUF_SIZE) {
					fprintf(stderr, "\nE: export name on server too long\n");
					exit(EXIT_FAILURE);
				}
				if(read(sock, buf, lenn) < 0) {
					fprintf(stderr, "\nE: could not read export name from server\n");
					exit(EXIT_FAILURE);
				}
				buf[lenn] = 0;
				printf("%s", buf);
				len -= lenn;
				len -= sizeof(lenn);
				if(len > 0) {
					if(read(sock, buf, len) < 0) {
						fprintf(stderr, "\nE: could not read export description from server\n");
						exit(EXIT_FAILURE);
					}
					buf[len] = 0;
					printf(": %s\n", buf);
				} else {
					printf("\n");
				}
			}
		}
	} while(reptype != NBD_REP_ACK);
	send_request(sock, NBD_OPT_ABORT, 0, NULL);
}

static void parse_sizes(char *buf, uint64_t *size, uint16_t *flags) {
	memcpy(size, buf, sizeof(*size));
	*size = ntohll(*size);
	buf += sizeof(*size);
	memcpy(flags, buf, sizeof(*flags));
	*flags = ntohs(*flags);

	if ((*size>>12) > (uint64_t)~0UL) {
		printf("size = %luMB", (unsigned long)(*size>>20));
		err("Exported device is too big for me. Get 64-bit machine :-(\n");
	} else {
		printf("size = %luMB", (unsigned long)(*size>>20));
	}
	printf("\n");
}

static void send_opt_exportname(int sock, u64 *rsize64, uint16_t *flags,
		bool can_opt_go, char* name, uint16_t global_flags) {
	send_request(sock, NBD_OPT_EXPORT_NAME, -1, name);
	char b[sizeof(*flags) + sizeof(*rsize64)];
	if(readit(sock, b, sizeof(b)) < 0 && can_opt_go) {
		err("E: server does not support NBD_OPT_GO and dropped connection after sending NBD_OPT_EXPORT_NAME. Try -g.");
	}
	parse_sizes(b, rsize64, flags);
	if(!(global_flags & NBD_FLAG_NO_ZEROES)) {
		char buf[125];
		readit(sock, buf, 124);
	}
}


void negotiate(int *sockp, u64 *rsize64, uint16_t *flags, char* name,
		uint32_t needed_flags, uint32_t client_flags, uint32_t do_opts,
		char *certfile, char *keyfile, char *cacertfile,
		char *tlshostname, bool tls, bool can_opt_go) {
	u64 magic;
	uint16_t tmp;
	uint16_t global_flags;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";
	int sock = *sockp;

	printf("Negotiation: ");
	readit(sock, buf, 8);
	if (strcmp(buf, INIT_PASSWD))
		err("INIT_PASSWD bad");
	printf(".");
	readit(sock, &magic, sizeof(magic));
	magic = ntohll(magic);
	if (magic != opts_magic) {
		if(magic == cliserv_magic) {
			err("It looks like you're trying to connect to an oldstyle server. This is no longer supported since nbd 3.10.");
		}
	}
	printf(".");
	readit(sock, &tmp, sizeof(uint16_t));
	global_flags = ntohs(tmp);
	if((needed_flags & global_flags) != needed_flags) {
		/* There's currently really only one reason why this
		 * check could possibly fail, but we may need to change
		 * this error message in the future... */
		fprintf(stderr, "\nE: Server does not support listing exports\n");
		exit(EXIT_FAILURE);
	}

	if (global_flags & NBD_FLAG_NO_ZEROES) {
		client_flags |= NBD_FLAG_C_NO_ZEROES;
	}
	client_flags = htonl(client_flags);
	if (write(sock, &client_flags, sizeof(client_flags)) < 0)
		err("Failed/2.1: %m");

#if HAVE_GNUTLS && !defined(NOTLS)
        /* TLS */
        if (tls) {
		int plainfd[2]; // [0] is used by the proxy, [1] is used by NBD
		tlssession_t *s = NULL;
		int ret;
		uint32_t tmp32;
		uint64_t tmp64;

		send_request(sock, NBD_OPT_STARTTLS, 0, NULL);

		if (read(sock, &tmp64, sizeof(tmp64)) < 0)
			err("Could not read cliserv_magic: %m");
		tmp64 = ntohll(tmp64);
		if (tmp64 != NBD_OPT_REPLY_MAGIC) {
			err("reply magic does not match");
		}
		if (read(sock, &tmp32, sizeof(tmp32)) < 0)
			err("Could not read option type: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_OPT_STARTTLS)
			err("Reply to wrong option");
		if (read(sock, &tmp32, sizeof(tmp32)) < 0)
			err("Could not read option reply type: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_REP_ACK) {
			err("Option reply type != NBD_REP_ACK");
		}
		if (read(sock, &tmp32, sizeof(tmp32)) < 0) err(
			"Could not read option data length: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != 0) {
			err("Option reply data length != 0");
		}
		s = tlssession_new(0,
				   keyfile,
				   certfile,
				   cacertfile,
				   tlshostname,
				   !cacertfile || !tlshostname, // insecure flag
#ifdef DODBG
				   1, // debug
#else
				   0, // debug
#endif
				   NULL, // quitfn
				   NULL, // erroutfn
				   NULL // opaque
			);
		if (!s)
			err("Cannot establish TLS session");

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, plainfd) < 0)
			err("Cannot get socket pair");

		if (set_nonblocking(plainfd[0], 0) <0 ||
		    set_nonblocking(plainfd[1], 0) <0 ||
		    set_nonblocking(sock, 0) <0) {
			close(plainfd[0]);
			close(plainfd[1]);
			err("Cannot set socket options");
		}

		ret = fork();
		if (ret < 0)
			err("Could not fork");
		else if (ret == 0) {
			// we are the child
			if (daemon(0, 0) < 0) {
				/* no one will see this */
				fprintf(stderr, "Can't detach from the terminal");
				exit(1);
			}
			signal (SIGPIPE, SIG_IGN);
			close(plainfd[1]);
			tlssession_mainloop(sock, plainfd[0], s);
			close(sock);
			close(plainfd[0]);
			exit(0);
		}
		close(plainfd[0]);
		close(sock);
		sock = plainfd[1]; /* use the decrypted FD from now on */
		*sockp = sock;
	}
#else
	if (keyfile) {
		err("TLS requested but support not compiled in");
	}
#endif

	if(do_opts & NBDC_DO_LIST) {
		ask_list(sock);
		exit(EXIT_SUCCESS);
	}

	struct reply *rep = NULL;
	
	if(!can_opt_go) {
		send_opt_exportname(sock, rsize64, flags, can_opt_go, name, global_flags);
		return;
	}

	send_info_request(sock, NBD_OPT_GO, 0, NULL, name);

	do {
		if(rep != NULL) free(rep);
		rep = read_reply(sock);
		if(rep && (rep->reply_type & NBD_REP_FLAG_ERROR)) {
			switch(rep->reply_type) {
				case NBD_REP_ERR_UNSUP:
					/* server doesn't support NBD_OPT_GO or NBD_OPT_INFO,
					 * fall back to NBD_OPT_EXPORT_NAME */
					send_opt_exportname(sock, rsize64, flags, can_opt_go, name, global_flags);
					free(rep);
					return;
				case NBD_REP_ERR_POLICY:
					if(rep->datasize > 0) {
						char errstr[1024];
						snprintf(errstr, sizeof errstr, "Connection not allowed by server policy. Server said: %s", rep->data);
						err(errstr);
					} else {
						err("Connection not allowed by server policy.");
					}
					free(rep);
					exit(EXIT_FAILURE);
				default:
					if(rep->datasize > 0) {
						char errstr[1024];
						snprintf(errstr, sizeof errstr, "Unknown error returned by server. Server said: %s", rep->data);
						err(errstr);
					} else {
						err("Unknown error returned by server.");
					}
					free(rep);
					exit(EXIT_FAILURE);
			}
		}
		uint16_t info_type;
		switch(rep->reply_type) {
			case NBD_REP_INFO:
				memcpy(&info_type, rep->data, 2);
				info_type = htons(info_type);
				switch(info_type) {
					case NBD_INFO_EXPORT:
						parse_sizes(rep->data + 2, rsize64, flags);
						break;
					default:
						// ignore these, don't need them
						break;
				}
				break;
			case NBD_REP_ACK:
				break;
			default:
				err_nonfatal("Unknown reply to NBD_OPT_GO received, ignoring");
		}
	} while(rep->reply_type != NBD_REP_ACK);
	free(rep);
}
