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
#include <math.h>
#include <pthread.h>

#include <tls.h>



struct bloom {
	int bits;
};
	pthread_mutex_t lock;
	struct sockaddr_in sockname, server_sa;
	char buffer[80], *ep;
	size_t maxread;
	struct sigaction sa;
	int serverCall[1] = {0};
	int sd, i, ssd,t;
	char bloom[40] = {0};
	unsigned int fileLen;
	socklen_t clientlen;
	u_short port;
	u_short serverport;
	pid_t pid;
	u_long p;
	u_long sp;
	struct tls_config *tls_cfg = NULL; // TLS config
	struct tls_config *tls_scfg = NULL; //TLS server config
	struct tls *tls_ctx = NULL; // TLS context
	struct tls *tls_cctx = NULL; // client's TLS context
	struct tls *tls_sctx = NULL; // server's TLS context
	int clientsd;

unsigned int murmur_32_scramble(unsigned int k) {
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}
unsigned int murmurhash2(const char* key, size_t len, unsigned int seed)
{
	unsigned int h = seed;
    unsigned int k;
    /* Read in groups of 4. */
	size_t i;
    for (i = len >> 2; i; i--) {
        // Here is a source of differing results across endiannesses.
        // A swap here has no effects on hash properties though.
        memcpy(&k, key, sizeof(unsigned int));
        key += sizeof(unsigned int);
        h ^= murmur_32_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    /* Read the rest. */
    k = 0;
	
    for (i = len & 3; i; i--) {
        k <<= 8;
        k |= key[i - 1];
    }
    // A swap is *not* necessary here because the preceding loop already
    // places the low bytes in the low places according to whatever endianness
    // we use. Swaps only apply when the memory is copied in a chunk.
    h ^= murmur_32_scramble(k);
    /* Finalize. */
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h % 16;
}

unsigned int FNVHash(const char* str, unsigned int length) {
	const unsigned int fnv_prime = 0x811C9DC5;
	unsigned int hash = 0;
	unsigned int i = 0;

	for (i = 0; i < length; str++, i++)
	{
		hash *= fnv_prime;
		hash ^= (*str);
	}

	return hash % 16;
}

//returnn 1 if may be cached return 0 if not
int bloom_query (char* bloom, const char* buffer){
	unsigned int a,b,len,i;
	len = strlen(buffer);
	a = murmurhash2(buffer, len, 17);
	b = FNVHash(buffer, len);
	printf("query: %d %d\n",a,b);
	i = 1 & (bloom[a / 8] >> (a % 8));
	//printf("%d\n", i);
	if( (1 & (bloom[a / 8] >> (a % 8) )) && (1 & (bloom[b / 8] >> (b % 8) ) )){
		printf("file might be cached\n");
		return 1;
	} else {
		printf("file not cached reciving from server\n");
		return 0;
	}
}	

int bloom_insert (char* bloom, const char* buffer){
	unsigned int a,b,len,i;
	len = strlen(buffer);
	a = murmurhash2(buffer, len, 17);
	b = FNVHash(buffer, len);
	printf("insert: %d %d\n",a,b);
	bloom[a / 8] ^= 1 << (a % 8 );
	bloom[b / 8] ^= 1 << (b % 8 );
	i = 1 & (bloom[a / 8] >> (a % 8));
	//printf("%d\n", i);
	return 1;

}

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber serverportnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

void *threadFunc(){
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		*/
	pthread_mutex_lock(&lock);
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
			//client proxy communication testing
// 			printf("file found, sending contents of : ");
// 			printf(buffer);
// 			printf(" to the client\n");
			
			//create bloom fliter
			fileLen = strlen(buffer);
			if(bloom_query(bloom, buffer)){
				printf("sending contents of %s to the client\n", buffer);
			} else {
				bloom_insert(bloom, buffer);
				printf("retrieving contents of %s from server then string to client\n", buffer);
			}
				

			strncpy(buffer,
	    			"It was the best of times, it was the worst of times... \n",
	    		sizeof(buffer));
			

			//TODO FLITER
			//TODO CONNECTION TO SERVER	
			//new TLS for proxy and server
			if((tls_scfg = tls_config_new()) == NULL)
				errx(1 ," unable to allocate TLS config");
			if(tls_config_set_ca_file(tls_scfg, "/home/csmajs/dgunn001/CS165/TLSCache-master/certificates/root.pem") == -1)
				errx(1, "unable to set root CA file");
			
			if((tls_sctx = tls_client()) == NULL)
				errx(1, "tls client creation failed");
			if(tls_configure(tls_sctx, tls_scfg) == -1)
				errx(1, "tls configureation failed (%s)" , tls_error(tls_sctx));
			   
			 memset(&server_sa, 0, sizeof(server_sa));
			server_sa.sin_family = AF_INET;
			server_sa.sin_port = htons(serverport);
			server_sa.sin_addr.s_addr = htonl(INADDR_ANY);
			ssd=socket(AF_INET,SOCK_STREAM,0);  
			
			if(connect(ssd, (struct sockaddr*)&server_sa, sizeof(server_sa)) == - 1)
				     errx(1, "server connect failed");
			if(tls_connect_socket(tls_sctx,ssd,"localhost") == -1)
				     errx(1, "tls connection failed(%s)", tls_error(tls_sctx));
					  
			do{
				if((i = tls_handshake(tls_sctx)) == -1)
					errx(1, "tls handshake failed (%s)" , tls_error(tls_sctx));
			} while (i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			
			//SET UP WRITING TO SERVER (FILENAME)
			r = -1;
			rc = 0;
			maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
			while ((r != 0) && rc < maxread) {
			//printf("reading");
				r = tls_write(tls_sctx, buffer + rc, maxread - rc);
				if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
					continue;
				if (r < 0) {
					err(1, "tls_write failed (%s)", tls_error(tls_sctx));
				} else
					rc += r;
			}
			//SET UP READING FROM SERVER
			r = -1;
			rc = 0;
			maxread = sizeof(buffer) - 1; /* leave room for a 0 byte */
			while ((r != 0) && rc < maxread) {
				//printf("reading");
				r = tls_read(tls_sctx, buffer + rc, maxread - rc);
				if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
					continue;
				if (r < 0) {
					err(1, "tls_read failed (%s)", tls_error(tls_sctx));
				} else
					rc += r;
			}
			/*
			 * we must make absolutely sure buffer has a terminating 0 byte
			 * if we are to use it as a C string
			 */
			buffer[rc] = '\0';

			printf("Server sent:  %s",buffer);
	
			close(ssd);		     
				     
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
	pthread_mutex_unlock(&lock);
}

int main(int argc,  char *argv[])
{
	if(pthread_mutex_init(&lock, NULL) !=0){
		printf("\n mutex init has failed\n");
		       return 1;
	}
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
	
			
		struct sockaddr_in client;
		
		clientlen = sizeof(&client);
		
		
		if (clientsd == -1)
			err(1, "accept failed");
	while(clientsd = accept(sd, (struct sockaddr *)&client, &clientlen)) {
		void *ret;
		pthread_t tid;
		pthread_create(&tid, NULL, threadFunc, (void*) &tid);
	}

}
