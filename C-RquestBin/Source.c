#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>
#include <string.h>
#include "Header.h"


#define WIN32_MEAN_AND_LEAN

int __cdecl main()
{

	WSADATA wsadata; //windows socket structure
	WORD versionRequest;
	int err;
	
	versionRequest = MAKEWORD(2, 2);
	err = WSAStartup(versionRequest, &wsadata);
	
	if (err != 0) //The WSAStartup function initiates use of the Winsock DLL by a process.
	{
		printf_s("WSAStartup failed. err = %d \n",err);
		exit(0);
	}

	if (LOBYTE(wsadata.wVersion)!=2 || HIBYTE(wsadata.wVersion !=2))
	{
		printf_s("Could not find usable version of Winsock.dll");
		exit(0);
	}
	else
	{
		printf("The Winsock 2.2 dll was found okay\n\n");
	}

	RequestHeaders();

	printf_s("%s", string);

	return 0x1;
}

void RequestHeaders()
{
	SOCKET Socket = INVALID_SOCKET;
	SOCKADDR_IN SockAddr;
	HOSTENT* pHostent;
	const char* host;
	int err;

	host = HOST;
	pHostent = gethostbyname(host);

	if (!(pHostent))
	{
		printf_s("Could not resolve hostname !\n");
	}

	SockAddr.sin_family = AF_INET;
	SockAddr.sin_port = htons(SERVER_PORT);
	SockAddr.sin_addr.S_un.S_addr = *((unsigned long*)pHostent->h_addr_list[0]);

	
	Socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if (Socket == INVALID_SOCKET)
	{
		printf_s("Could not create Socket !!\n");
		WSACleanup();
		exit(0);
	}
	err = connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr));
	if (err !=0)
	{
		printf_s("Could not connect !!\n");
		WSACleanup();
		exit(0);
	}

	err = send(Socket, HEAD_REQUEST, sizeof(HEAD_REQUEST) - 1, 0); //send request
	printf_s("%s",HEAD_REQUEST);
	if (err == SOCKET_ERROR)
	{
		printf_s("Could not send !!\n");
		WSACleanup();
		exit(0);
	}

	/*err = send(Socket, host, lstrlen(host), 0); //send Hostname
	if (err == SOCKET_ERROR)B
	{
		printf_s("Could not send !!\n");
		WSACleanup();
		exit(0);
	}
	
	err = send(Socket,HEAD_REQUEST2,sizeof(HEAD_REQUEST2)-1,0);
	if (err == SOCKET_ERROR)
	{
		printf_s("Could not send !!\n");
		WSACleanup();
		exit(0);
	}

	err = shutdown(Socket,SD_SEND);
	if (err==SOCKET_ERROR)
	{
		printf_s("Could not shutdown !!\n");
		closesocket(Socket);
		WSACleanup();
	}*/

	int receive;
	while(receive = recv(Socket, BUFFER, 1000, 0) > 0)
	{
		if (receive == SOCKET_ERROR)
		{
			printf_s("Socket error while receiving !!\n");
		}
		else
		{
			int i = 0;
			while (BUFFER[i] >= 32 || BUFFER[i] == '\n' || BUFFER[i] == '\r') {

				string[i] += BUFFER[i];
				i += 1;
			//	printf_s("%c", string[i]);
			}
		}
	}

	err = shutdown(Socket, SD_SEND);
	if (err == SOCKET_ERROR)
	{
		printf_s("Could not shutdown !!\n");
		closesocket(Socket);
		WSACleanup();
	}

}
