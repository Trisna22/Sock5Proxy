/**
	Sock5 proxy server

*/

#include "stdafx.h"
#include "Sock5Proxy.h"

int main(int argc, char* argv[]) {

	// Implement an option parser for port/authentication/proxy type

	printf("[#] Starting proxy server on port 1080!\n\n");

	int serverSocket;
	if (argc == 1) {
		if ((serverSocket = Sock5Proxy::startProxy()) == SOCKET_ERROR) {
			return 0;
		}
	}
	else if (argc == 2) {
		int port = atoi(argv[1]);
		if ((serverSocket = Sock5Proxy::startProxy(port)) == SOCKET_ERROR) {
			return 0;
		}
	}
	else {
		printf("Sock5 Proxy\n\n");
		printf("Usage: %s [port number]\n\n", argv[0]);
		return 0;
	}

	return Sock5Proxy::handleClients(serverSocket);
}