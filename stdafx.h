#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <stdio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

inline void debug_printf(const char* fmt, ...) {
	char message[4096];
	char finalMessage[4200];

	struct tm t;
	time_t now = time(nullptr);
	localtime_s(&t, &now);

	va_list args;
	va_start(args, fmt);
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	snprintf(
		finalMessage,
		sizeof(finalMessage),
		"[%02d:%02d:%02d] (#%d) %s",
		t.tm_hour,
		t.tm_min,
		t.tm_sec,
		GetCurrentThreadId(),
		message
	);

	//OutputDebugStringA(finalMessage);

	// Optional: also print to console
	fputs(finalMessage, stdout);
}

#define dbgprintf(...) debug_printf(__VA_ARGS__)