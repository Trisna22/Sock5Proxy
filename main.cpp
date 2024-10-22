/**
	Sock5 proxy server
*/

#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include "Sock5Proxy.h"


void printUsage(const char* progamName) {

	printf("Usage: %s [options]\n", progamName);
	printf("Options:\n"); 
	printf("  -h, --help               Print this help message.\n");
	printf("  -p, --port PORT          Port to host proxy on.\n");
	printf("  -v, --verbose            Set verbose output.\n");
	printf("  -u, --username USERNAME  Sets username authentication.\n");
	printf("  -P, --password PASSWORD  Sets password authentication.\n");
}

bool isValidPort(char* arg) {

	int port = atoi(arg);
	return port >= 1 && port <= 65535;
}

int main(int argc, char* argv[]) {

	// Implement an option parser for port/authentication/proxy type

	int serverSocket, port = 1080;
	char* username = NULL, *password = NULL;
	bool verbose = false;

	for (int i = 1; i < argc; i++) {

		std::string arg = argv[i];
		if (arg == "-h" || arg == "--help") {
			printUsage(argv[0]);
			return 0;
		}

		// Argument for PORT given.
		if (arg == "-p" || arg == "--port") {
			
			// First check if there is an next argument.
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				
				if (!isValidPort(argv[i + 1])) {
					printf("Invalid port number given!\n");
					return 0;
				}

				port = atoi(argv[++i]);
				i++;
				continue;
			}
			else {
				printf("ArgumentError: --port option requires a valid port number!\n");
				return 0;
			}
		}

		// Argument for verbose level.
		if (arg == "-v" || arg == "--verbose") {
			verbose = true;
			continue;
		}

		// Argument for USERNAME given.
		else if (arg == "-u" || arg == "--username") {

			if (i + 1 < argc && argv[i + 1][0] != '-') {

				int lenUsername;
				char* optUsername = argv[++i];
				if ((lenUsername = strlen(optUsername)) > 0) {

					username = (char*)malloc(lenUsername) + 1;
					strncpy(username, optUsername, lenUsername +1); // Don't forget the null pointer.
					continue;
				}
				else {
					printf("ArgumentError: --username option requires a valid username!\n");
					return 0;
				}
			}
			else {
				printf("ArgumentError: --username option requires a valid username!\n");
				return 0;
			}
		}

		// Argument for PASSWORD given.
		else if (arg == "-P" || arg == "--password") {

			if (i + 1 < argc && argv[i + 1][0] != '-') {

				int lenPassword;
				char* optPassword = argv[++i];
				if ((lenPassword = strlen(optPassword)) > 0) {

					password = (char*)malloc(lenPassword) + 1;
					strncpy(password, optPassword, lenPassword +1); // Don't forget the null pointer.
					continue;
				}
				else {
					printf("ArgumentError: --password option requires a valid username!\n");
					return 0;
				}
			}
			else {
				printf("ArgumentError: --password option requires a valid username!\n");
				return 0;
			}
		}
		else {
			printf("ArgumentError: Unknown argument given! [%s]\n", argv[i]);
			return 0;
		}
	}

	// Check if password and username is both given.
	if ((username != NULL && password == NULL) || 
		(password != NULL && username == NULL)) {
		printf("Both username and password needs to be specified\n");
		printf("in order to make use of authentication.\n");
		return 0;
	}

	printf("Starting SOCK5 proxy on port %d\n", port);
	if ((serverSocket = Sock5Proxy::startProxy(port)) == SOCKET_ERROR) {
		return 0;
	}
	
	return Sock5Proxy::handleClients(serverSocket, username, password);
}