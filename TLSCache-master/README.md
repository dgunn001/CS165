## TLS Cache
------------------------

This repository contains the CS165 project for Darrien Gunn and Surya Kumaraguru. The directory structure is as follows:
```
certificates/	// Contains CA and server certificates.
scripts/	// Helper scripts.
src/		// Client, Proxy and Server code. Add your code here.
cmake/		// CMake find script. 
extern/		// Required third party tools and libraries- LibreSSL & CMake.
licenses/	// Open source licenses for code used.
```


### Steps
-------------------------
1. Download and extract the code.
2. Run the following commands:
```
$ cd TLSCache
$ source scripts/setup.sh

Generate the server and client certificates
$ cd certificates
$ make
```
3. The plaintext server and client can be used as follows:
```
$ cd TLSCache

Run the server:
$ ./build/src/server 9999

Run the proxies: (our code is designed for 6 proxies following the diagram)
$ ./build/src/server 9993-8


Run the client (in another terminal):
$ ./build/src/client 127.0.0.1 9999
```
### Scripts included
--------------------------
1. `setup.sh` should be run exactly once after you have downloaded code, and never again. It extracts and builds the dependencies in extern/, and builds and links the code in src/ with LibreSSL.
2. `reset.sh` reverts the directory to its initial state. It does not touch `src/` or `certificates/`. Run `make clean` in `certificates/` to delete the generated certificates.

### Code Added
--------------------------
Cilent
*Added File sending to Proxy
*Added Rendezvous Hashing

Proxy
*Create Proxy file
*Added read and write to client as well as read from server
*Added two way interfacing. More sockets

Server
*Added reading from clients


