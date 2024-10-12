#pragma once

#include "stdafx.h"

/**
 * Lightweight implementation of Socks protocol version 5 
 * 
 * This project is taken from my other project, the C2 server Odysseus.
 *
 * RFC: https://datatracker.ietf.org/doc/html/rfc1928
 * C2: https://github.com/Trisna22/Odysseus
 * 
 * Example source code from C2 BOF is at /Odysseus_Sock5Proxy_example_bof.cpp
 */

#ifndef SOCK5_PROXY_H
#define SOCK5_PROXY_H n 

#define DEFAULT_PROXY_PORT				1080
#define ARRAY_INIT                      {0}
#define ARRAY_SIZE (x)                  (sizeof(x) / sizeof(x[0]))
#define MAX_BUFFER_SIZE                 65536

typedef uint8_t uint128_t[16];  // For IPv6 addresses.

// For setting the error code on linux builds.
#ifndef WIN32
	int WSAGetLastError() {
		return errno;
	}
#endif 


class Sock5Proxy {
private:
	// SOCKS versions
	enum ver : uint8_t {
		SOCKS4 = 0x04,
		SOCKS5 = 0x05
	};

	// SOCK5 authentication methods
	enum AuthMethods : uint8_t {
		NOAUTH = 0x00,
		GSSAPI = 0x01,
		USER_PASSWORD = 0x02,
		NO_ACCEPTABLE = 0xFF
	};

	// SOCK5 commands
	enum Command : uint8_t {
		CONNECT = 0x01,
		BIND = 0x02,
		UDP_ASSOCIATE = 0x03
	};

	// SOCK5 address type.
	enum AddressType : uint8_t {
		IPV4 = 0x01,
		FQDN = 0x03,
		IPV6 = 0x04,
	};

	// SOCK5 command reply
	enum CommandReply : uint8_t {
		OK = 0x00,
		ERR = 0x01,
		RULE_BLOCK = 0x02,
		NETWORK_UNREACHABLE = 0x03,
		HOST_UNREACHABLE = 0x04,
		CONNECTION_REFUSED = 0x05,
		TTL_EXPIRED = 0x06,
		CMD_NOT_SUPPORTED = 0x07,
		ADDR_NOT_SUPPORTED = 0x08,
		UNASSIGNED = 0xFF
	};

	/**
	*	All structs for invitation handshake (authentication methods).
	*/
	struct InvitationRequest {

		uint8_t version;       // Proxy version to use.
		uint8_t nmethods;      // Number of methods.

	} SOCK5_INV_REQUEST;
	struct InvitationResponse {
		uint8_t version;       // Proxy version to use.
		uint8_t method;        // Method to use.
	} SOCK5_INV_RESPONSE;

	/**
	 * All structs for proxy commands.
	 */

	 // IP version 4.
	struct IPv4 {
		uint32_t ip;
		uint16_t port;
	} ipv4;

	// IP version 6.
	struct IPv6 {
		uint128_t ip;
		uint16_t port;
	} ipv6;

	// Domain name.
	struct FQDN {
		uint8_t bytes[4];
	} fqdn;

	struct CommandRequest {
		uint8_t version;       // Proxy version to use.
		uint8_t command;       // The proxy command.
		uint8_t reserved;
		uint8_t addrType;      // The internet address type.
	} SOCK5_COMMAND;

	struct CommandResponse {
		uint8_t version;
		uint8_t reply;
		uint8_t reserved;
		uint8_t addrType;
		// union BND {

		//     struct IPv4 ipv4;
		//     struct IPv6 ipv6;
		//     struct FQDN fqdn;

		// } BindAddress;

	} SOCK5_COMMAND_REPLY;

	#pragma pack(push, 1)

private:
	int clientSocket;
	char* proxyUsername;
	char* proxyPassword;
	AuthMethods authMethod;
	struct SOCK5ThreadParams {
		int clientSocket;
	};

	/**
	 *	Exit thread gracefully.
	 */
	void exitThread() {

#ifdef WIN32
		closesocket(this->clientSocket);
		ExitThread(0);
#else
		close(this->clientSocket);
		pthread_exit(0);
#endif
	}

	/**
	 *	Receive any object from client socket.
	 */
	template<typename T>
	T receiveObject(int* red) {

		T obj;

#ifdef WIN32

		char* data = new char[sizeof(T)];
		if ((*red = recv(this->clientSocket, data, sizeof(T), 0)) == SOCKET_ERROR) {

			// Check if it is a blocking issue.
			if (WSAGetLastError() == WSAEWOULDBLOCK) {
				Sleep(100);
				return receiveObject<T>(red); // Do again.
			}

			printf("[!] Failed to receive proxy object! Error code: %d\n", WSAGetLastError());
			this->exitThread();
		}

		T *tempObj = reinterpret_cast<T*>(data);
		obj = *tempObj;
#else
		if ((*red = recv(this->clientSocket, &obj, sizeof(T), NULL)) <= 0) {
			printf("[!] Failed to receive proxy object! Error code: %d\n", errno);
			this->exitThread();
		}
#endif

		return obj;
	}

	/**
	 *	Send any object to client socket.
	 */
	template<typename T>
	void sendObject(T obj, int size) {
#ifdef WIN32

		if (send(this->clientSocket, (char*) &obj, size, 0) == SOCKET_ERROR) {
			printf("[!] Failed to send proxy object! Error code: %d\n", WSAGetLastError());
		}
#else
		if (send(this->clientSocket, &obj, size, NULL) == SOCKET_ERROR) {
			printf("[!] Failed to send proxy object! Error code: %d\n", errno);
		}
#endif
	}

	/**
	 *	Send IP & PORT response.
	 */
	void sendIPResponse(const char* ip, unsigned short int port) {

		send(this->clientSocket, ip, 4, 0);
		send(this->clientSocket, (char*)&port, sizeof(port), 0);
	}

	/**
	 *	Handle SOCK5 authentication.
	 */
	void handleSOCK5Authentication() {
		switch (this->authMethod)
		{
		case AuthMethods::NOAUTH: {

			// Send response its fine.
			InvitationResponse response = {
				ver::SOCKS5,
				AuthMethods::NOAUTH
			};

			sendObject<InvitationResponse>(response, sizeof(InvitationResponse));
			break;
		}

		case AuthMethods::USER_PASSWORD: {

			printf("[!] USERNAME PASSWORD authentication not yet implemented!\n");
			this->exitThread();
			break;
		}
		}
	}

	/**
	 *	Convert uint32 to IP address.
	*/
	static char* parseIPv4(uint32_t value) {
		
		char* IP = new char[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &value, IP, INET_ADDRSTRLEN) == NULL) {
			printf("[-] Failed to parse the IPv4 address! Error code: %d\n", WSAGetLastError());
			return NULL;
		}

		return IP;
	}

	/**
	 *	Parses domain from client.
	*/
	char* parseDomain() {

		int red;
		unsigned char size;

		size = this->receiveObject<unsigned char>(&red);

		char* name = (char*)malloc((sizeof(char) * size) + 1);
		if (recv(this->clientSocket, name, size, 0) <= 0) {
			printf("[-] Failed to receive the app domain to connect to! Error code: %d\n", WSAGetLastError());
			return NULL;
		}

		name[size] = '\0';
		return name;
	}

	/**
	 *	Parses the port from domain.
	*/
	UINT16 parsePortDomain() {

		UINT16 port = 0;
		if (recv(this->clientSocket, (char*)&port, sizeof(UINT16), 0) <= 0) {
			printf("[-] Failed to receive the app port to connect to! Error code: %d\n", WSAGetLastError());
			return NULL;
		}

		return htons(port);
	}

	/**
	 *	Resolves domain name to IP.
	*/
	char* resolveDomain(char* domain) {
		
		ADDRINFOA hints;
		ADDRINFOA* result;
		ZeroMemory(&hints, sizeof(ADDRINFOA));

		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		if (GetAddrInfoA(domain, "1", &hints, &result) != 0) {
			printf("[-] Failed to get address information about domain name! Error code: %d\n", WSAGetLastError());
			return NULL;
		}

		char *IP = (char*)malloc(INET_ADDRSTRLEN);

		// Get the first one from the list if possible.
		for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

			// Only IPv4 addresses.
			if (ptr->ai_family == AF_INET) {

				sockaddr_in* sockaddr = (sockaddr_in*)ptr->ai_addr;
				inet_ntop(AF_INET, &(sockaddr->sin_addr), IP, INET_ADDRSTRLEN);
				break;
			}

		}

		return IP;
	}

	/**
	 *	Proxy connect to an app with IP and port.
	*/
	int proxyConnect(int addrType, char* ip, int port) {
		int red, appSock = SOCKET_ERROR;

		// Construct struct for connecting.
		struct sockaddr_in remote;
		ZeroMemory(&remote, sizeof(sockaddr_in));
		remote.sin_port = htons(port);
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(ip);

		// Connect to remote address.
		printf("[!] Connecting to app %s:%d\n", ip, port);

		appSock = socket(AF_INET, SOCK_STREAM, NULL);
		if (appSock == SOCKET_ERROR) {
			printf("[-] Failed to create app socket! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		if (connect(appSock, (sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {

			printf("[-] Failed to connect to the app! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		return appSock;
	}

	/**
	 *	Proxy pipe the connection between the app and the client.
	*/
	void pipeSocketApp(int clientSock, int appSocket) {

		// The biggest file descriptor is what we are looking for.
		int maxFD = (clientSock > appSocket) ? clientSock : appSocket;

		// Setup read/write variables.
		fd_set readSet;
		char buffer[MAX_BUFFER_SIZE];

		for (;;) {
			FD_ZERO(&readSet);
			FD_SET(clientSock, &readSet);
			FD_SET(appSocket, &readSet);
			int ret = select(maxFD, &readSet, NULL, NULL, NULL);

			if (ret < 0 && errno == EINTR) {
				continue;
			}

			// When app socket sends data.
			if (FD_ISSET(appSocket, &readSet)) {

				int nread = recv(appSocket, buffer, MAX_BUFFER_SIZE, 0);
				if (nread <= 0) {

					if (nread == 0) {
						printf("[-] App closed connection!\n");
					}
					else {
						printf("[-] Error reading from appSocket! Error code: %d\n", WSAGetLastError());
					}
					break;
				}

				// printf("[*] %d bytes appSocket => clientSocket\n", nread);

				// Send to client socket.
				if (send(clientSock, buffer, nread, NULL) == SOCKET_ERROR) {

					printf("[-] Error sending data client socket! Error code: %d\n", WSAGetLastError());
					break;
				}

				continue;
			}

			// When client socket sends data.
			if (FD_ISSET(clientSock, &readSet)) {

				int nread = recv(clientSock, buffer, MAX_BUFFER_SIZE, NULL);
				if (nread <= 0) {
					if (nread == 0) {
						printf("[-] Client closed connection!\n");
					}
					else {
						printf("[-] Error reading from client! Error code: %d\n", errno);
					}
					break;
				}

				 //printf("[*] %d bytes clientSocket => appSocket\n", nread);

				// Send to app socket.
				if (send(appSocket, buffer, nread, NULL) == SOCKET_ERROR) {

					printf("[-] Error sending data to app socket! Error code: %d\n", errno);
					break;
				}
			}
		}

		this->exitThread();
	}

public:

	Sock5Proxy(int sock) : clientSocket(sock) {}
	Sock5Proxy(int sock, char* username, char* password) : clientSocket(sock), proxyUsername(username), proxyPassword(password) {}

	~Sock5Proxy() {

#ifdef WIN32
			closesocket(this->clientSocket);
#else
			close(this->clientSocket);
#endif
	}

	/**
	*	Handles the initiation requests.
	*	RFC: https://datatracker.ietf.org/doc/html/rfc1928#section-3
	*/
	void invitation() {

		// Client sends us the version, number of methods and all the methods available.
		int sizeRead = 0;
		InvitationRequest inv = this->receiveObject<InvitationRequest>(&sizeRead);

		// Check if version compatible.
		if (sizeRead == 2 && inv.version != ver::SOCKS5 && inv.version != ver::SOCKS4) {

			printf("[#] They sent us {%hhX, %hhX}\n", inv.version, inv.nmethods);
			printf("[-] Incompatible with our version!\n");
			exitThread();
		}

		if (inv.version == ver::SOCKS5) {

			bool supported = false;

			// Check if auth method is supported by us.
			for (int i = 0; i < inv.nmethods; i++) {

				int red = 0;
				char type = this->receiveObject<char>(&red);

				// Check if client supports our chosen authentication method.
				if (type == this->authMethod) {
					supported = true;
				}
			}

			// If none of the methods are supported.
			if (!supported) {

				InvitationResponse response = {
					ver::SOCKS5,
					AuthMethods::NO_ACCEPTABLE
				};
				sendObject<InvitationResponse>(response, sizeof(InvitationResponse));
			}
			else {
				this->handleSOCK5Authentication();
				return; // Exit function instead of suicide.
			}

		}
		else if (inv.version == ver::SOCKS4) {

			printf("[-] Version not yet supported...\n");

		}
		else {
			printf("[-] Unsupported version!\n");
		}

		this->exitThread();
	}

	/**
	*	Handles incomming requests.
	*	RFC: https://datatracker.ietf.org/doc/html/rfc1928#section-4
	*/
	void handleRequests() {

		// Get the command from the client.
		char* IP = NULL;
		int red, port;
		CommandRequest request = this->receiveObject<CommandRequest>(&red);

		int appSocket = SOCKET_ERROR;

		// Based on command connect or
		switch (request.command) {
		case Command::CONNECT: {

			// Check if an domain is given instead of IP.
			if (request.addrType == AddressType::FQDN) {
				
				// Parse domain.
				char* domain = parseDomain();

				// Parse port.
				port = parsePortDomain();
				
				printf("[i] Got domain %s:%d\n", domain, port);

				// Resolve address.			
				IP = resolveDomain(domain);

				printf("[i] Resolved IP: %s\n", IP);
			}
			else {
				// Parse the addresses.
				IPv4 ipv4 = this->receiveObject<IPv4>(&red);
				IP = Sock5Proxy::parseIPv4(ipv4.ip);
				port = htons(ipv4.port);
			}

			appSocket = this->proxyConnect(request.addrType, IP, port);
			break;
		}

		case Command::BIND: {
			printf("[-] Proxy method BIND not supported yet!\n");

			CommandResponse response = {
				ver::SOCKS5,
				CommandReply::CMD_NOT_SUPPORTED,
				0x00, // Reserved
				request.addrType
			};

			this->sendObject<CommandResponse>(response, sizeof(response));
			this->sendIPResponse(" 0.0.0.0", 666);
			this->exitThread();
			break;
		}

		case Command::UDP_ASSOCIATE: {
			printf("[-] Proxy method UDP ASSOCIATE not supported yet!\n");

			CommandResponse response = {
				ver::SOCKS5,
				CommandReply::CMD_NOT_SUPPORTED,
				0x00, // Reserved
				request.addrType
			};

			this->sendObject<CommandResponse>(response, sizeof(response));
			this->sendIPResponse("0.0.0.0", 666);
			this->exitThread();
			break;
		}

		default: {
			printf("[-] Unknown proxy method: %hhx\n", request.command);

			CommandResponse response = {
				ver::SOCKS5,
				CommandReply::CMD_NOT_SUPPORTED,
				0x00, // Reserved
				request.addrType,
			};

			this->sendObject<CommandResponse>(response, sizeof(response));
			this->sendIPResponse("0.0.0.0", 666);
			this->exitThread();
			break;
		}
		}

		// Check if connection has been established.
		if (appSocket != SOCKET_ERROR) {

			// Send response OK
			CommandResponse response = {
				ver::SOCKS5,
				CommandReply::OK,
				0x00, // Reserved
				request.addrType
			};

			this->sendObject<CommandResponse>(response, sizeof(response));
			this->sendIPResponse("0.0.0.0", 666);

			// Pipe connection.
			pipeSocketApp(this->clientSocket, appSocket);

		}
	}

	/**
	*	Starts proxy server.
	*/
	static int startProxy(int PORT = DEFAULT_PROXY_PORT) {

		// Usually on port 1080.
		int serverSocket;

		// Initialize WSA.
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {

			printf("[-] Failed to initialize WinSock! Error code: %d\n", GetLastError());
			return SOCKET_ERROR;
		}

		if ((serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == 0) {

			printf("[-] Failed to create a socket! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		// Make sure to set the socket on non-blocking mode that allows multithreading.
		// Set host address as reusable.
		u_long mode = 1;
		ioctlsocket(serverSocket, FIONBIO, &mode);

		int option = 1;
		if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*) &option, sizeof(option))) {
			
			printf("[-] Failed to set socket option! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}
	
		// Create address that listens on ANY IP.
		SOCKADDR_IN address;
		ZeroMemory(&address, sizeof(SOCKADDR_IN));
		address.sin_family = AF_INET;
		address.sin_port = htons(PORT);
		address.sin_addr.s_addr = INADDR_ANY;

		if (bind(serverSocket, (SOCKADDR*)&address, sizeof(address))) {

			printf("[-] Failed to bind the proxy address! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		// Now listen for clients.
		if (listen(serverSocket, SOMAXCONN) < 0) {

			printf("[-] Failed to start listening for connections! Error code: %d\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		// Put the socket in non-blocking mode, so that we can use multiple threads with it.
		unsigned long on = 1;
		ioctlsocket(serverSocket, FIONBIO, &on);
		
		return serverSocket;
	}
	
	/**
	*	App loop
	*/
	static int handleClients(int serverSocket) {

		u_long mode = 1;
		SOCKADDR_IN remote;
		ZeroMemory(&remote, sizeof(SOCKADDR_IN));
		int remoteLen = sizeof(remote);

		for (;;) {

			// Accept a client.
			int clientSocket = accept(serverSocket, (SOCKADDR*)&remote, &remoteLen);
			if (clientSocket == INVALID_SOCKET) {
				if (WSAGetLastError() == WSAEWOULDBLOCK) {
					// No incoming sockept, non-blocking mode, so continue without blocking.
					Sleep(100);
					continue;
				}
				else {
					printf("[-] Failed to accept a client! Error code: %d\n", WSAGetLastError());
					return SOCKET_ERROR;
				}
			}

			printf("[!] Accepted new client connection.\n");

			// Set the client socket to non-blocking as well.
			ioctlsocket(clientSocket, FIONBIO, &mode);

			SOCK5ThreadParams params;
			params.clientSocket = clientSocket;
			if (CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Sock5Proxy::proxyClientHandler, &params, NULL, NULL) == INVALID_HANDLE_VALUE)
			{
				printf("[-] Failed to create a new thread for the client! Error code: %d\n", GetLastError());
				return SOCKET_ERROR;
			}
		}

		return 0;
	}

	/**
	*	Client thread handler.
	*
	* [param] -> int clientSocket;
	*/
	static DWORD WINAPI proxyClientHandler(LPVOID params) {
		
		SOCK5ThreadParams* threadParams = (SOCK5ThreadParams*)params;
		int clientSocket = threadParams->clientSocket;

		// Start SOCK5 protocol on new client.
		Sock5Proxy proxy(clientSocket);
		proxy.invitation();
		proxy.handleRequests();
		return 0;
	}
};

#endif // !SOCK5_PROXY_H