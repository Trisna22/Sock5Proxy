/**
	Sock5 proxy server

*/

#include "stdafx.h"
#include "Sock5Proxy.h"

int main(int argc, char* argv[]) {

	// Implement an option parser for port/authentication/proxy type
	if (argc > 1) {

	}


	printf("[#] Starting proxy server on port 1080!\n\n");

	int serverSocket;
	if ((serverSocket = Sock5Proxy::startProxy()) == SOCKET_ERROR) {
		return 0;
	}

	return Sock5Proxy::handleClients(serverSocket);
}