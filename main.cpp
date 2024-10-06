/**
	Sock5 proxy server

*/

#include "stdafx.h"
#include "Sock5Proxy.h"

int main(int argc, char* argv[]) {

	// Implement an option parser for port/authentication/proxy type

	int serverSocket;
	if (argc == 2) {

		int port = atoi(argv[1]);
		if (port == 0 || port == -1) {

			printf("Invalid port given!\n");
			printf("Usage: %s [port number]\n", argv[0]);
			return 0;
		}

		printf("Starting SOCK5 proxy on port %d\n", port);

		if ((serverSocket = Sock5Proxy::startProxy(port)) == SOCKET_ERROR) {
			return 0;
		}
	}
	else if (argc > 2) {

		printf("Usage: %s [port number]\n", argv[0]);
		return 0;
	}
	else {

		printf("Starting SOCK5 proxy on port 1080\n");
		if ((serverSocket = Sock5Proxy::startProxy()) == SOCKET_ERROR) {
			return 0;
		}
	}

	return Sock5Proxy::handleClients(serverSocket);
}