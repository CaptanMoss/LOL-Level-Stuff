#pragma once
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)


const int  REQ_WINSOCK_VER = 2;	// Minimum winsock version required
const char HOST[] = "7aebe78dcbdb992ddd2cf31e68c73778.m.pipedream.net";
const int  SERVER_PORT = 80;
const int HOST_BUFFER = 14;
const char BUFFER[1000];
char string[1000];


const char HEAD_REQUEST[] =
{
	"HEAD / HTTP/1.1\r\n" 			// Get root index from server
	"Host:172.217.169.142"		// Specify host name used
	"\r\n"							// End hostname header from part1
	"User-agent: ereborlugimli\r\n" // Specify user agent
	"Connection: close\r\n" 		// Close connection after response
	"\r\n"
};

/*const char HEAD_REQUEST2[] = //bunu sil 
{
	"\r\n"							// End hostname header from part1
	"User-agent: HeadReqSample\r\n" // Specify user agent
	"Connection: close\r\n" 		// Close connection after response
	"\r\n"							// Empty line indicating end of request
};*/

void RequestHeaders();
