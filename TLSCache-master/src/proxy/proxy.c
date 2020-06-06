#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tls.h>

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}


int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client, server_sa;
	char buffer[80], *ep;
	size_t maxread;
	struct sigaction sa;
	int sd, i;
	socklen_t clientlen;
	u_short port;
	u_short serverport;
	pid_t pid;
	u_long p;
	u_long sp;
	struct tls_config *tls_cfg = NULL; // TLS config
	struct tls *tls_ctx = NULL; // TLS context
	struct tls *tls_cctx = NULL; // client's TLS context
	struct tls *tls_sctx = NULL; // server's TLS context

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 3)
		usage();
		errno = 0;
        p = strtoul(argv[1], &ep, 10);
	
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[1]);
		usage();
	}
	
	sp = strtoul(argv[2], &ep, 10);      
	if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && sp == ULONG_MAX) || (sp > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */
	port = p;
	serverport = sp;

	/* set up TLS */
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "/home/csmajs/dgunn001/CS165/TLSCache-master/certificates/root.pem") == -1)
		errx(1, "unable to set root CA file");
	if (tls_config_set_cert_file(tls_cfg, "/home/csmajs/dgunn001/CS165/TLSCache-master/certificates/server.crt") == -1) 
		errx(1, "unable to set TLS certificate file, error: (%s)", tls_config_error(tls_cfg));
	if (tls_config_set_key_file(tls_cfg, "/home/csmajs/dgunn001/CS165/TLSCache-master/certificates/server.key") == -1)
		errx(1, "unable to set TLS key file");
	if ((tls_ctx = tls_server()) == NULL)
		errx(1, "TLS server creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "TLS configuration failed (%s)", tls_error(tls_ctx));

	/* the message we send the client */
	strncpy(buffer,
	    "It was the best of times, it was the worst of times... \n",
	    sizeof(buffer));

	
	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */


	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Proxy up and listening for connections on port %u\n", port);
	for(;;) {
		
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		
		if (clientsd == -1)
			err(1, "accept failed");
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */
		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
			ssize_t written, w,r ,rc;

			i = 0;
			if (tls_accept_socket(tls_ctx, &tls_cctx, clientsd) == -1)
				errx(1, "tls accept failed (%s)", tls_error(tls_ctx));
			else {
				do {
					if ((i = tls_handshake(tls_cctx)) == -1)
						errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
				} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			}
			
			/*
			 * RECEIVE FILE NAME FROM CLIENT
		 	*/
			r = -1;
			rc = 0;
			maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
			while ((r != 0) && rc < maxread) {
			//printf("reading");
				r = tls_read(tls_cctx, buffer + rc, maxread - rc);
				if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
					continue;
				if (r < 0) {
					err(1, "tls_read failed (%s)", tls_error(tls_cctx));
				} else
					rc += r;
			}
			//TODO FLITER
				/*
			 * first set up "server_sa" to be the location of the server
	 		*/
			memset(&server_sa, 0, sizeof(server_sa));
			server_sa.sin_family = AF_INET;
			server_sa.sin_port = htons(serverport);
			server_sa.sin_addr.s_addr = inet_addr(argv[2]);
			if (server_sa.sin_addr.s_addr == INADDR_NONE) {
				fprintf(stderr, "Invalid IP address %s\n", argv[2]);
				usage();
			}
			if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
				err(1, "socket failed");

			/* connect the socket to the server described in "server_sa" */
			printf(argv[2]);
			if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
				err(1, "connect failed");

			if ((tls_sctx = tls_client()) == NULL)
				errx(1, "tls client creation failed");
			if (tls_configure(tls_sctx, tls_cfg) == -1)
				errx(1, "tls configuration failed (%s)", tls_error(tls_sctx));
			if (tls_connect_socket(tls_sctx, sd, "localhost") == -1)
				errx(1, "tls connection failed (%s)", tls_error(tls_sctx));


			do {
				if ((i = tls_handshake(tls_sctx)) == -1)
					errx(1, "tls handshake failed (%s)", tls_error(tls_sctx));
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
				
			//TODO CONNECTION TO SERVER
			
			/*
			 * write the message to the client, being sure to
			 * handle a short write, or being interrupted by
			 * a signal before we could write anything.
			 */
			w = 0;
			written = 0;
			while (written < strlen(buffer)) {
				w = tls_write(tls_cctx, buffer + written,
				    strlen(buffer) - written);

				if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
					continue;

				if (w < 0) {
					errx(1, "TLS write failed (%s)", tls_error(tls_cctx));
				}
				else
					written += w;
			}
			i = 0;
			do {
				i = tls_close(tls_cctx);
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

			close(clientsd);
			exit(0);
		}
		close(clientsd);
	}
}
