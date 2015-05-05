// VulChat.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

WSADATA wsa;
SOCKET master, client_socket[30], s;
struct sockaddr_in server, address;
char *client[30];
//set of socket descriptors
fd_set readfds;

//length of addr
int addrlen;
char ip_address[INET_ADDRSTRLEN];

//max numbers of clients admit
#define MAX_CLIENTS 30

//size of our receive buffer, this is string length.
#define MAXRECV 1024

#define DEFAULT_PORT 8888

void init_client_socket()
{
	int i;
	for (i = 0; i < MAX_CLIENTS; i++)
	{
		client_socket[i] = 0;
		client[i] = "";
	}
}

void init_wind_socket()
{
	printf("[*] Initialising Winsock VulChat v0.0.1 \n");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("[-] Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
}

void create_socket()
{
	//Create a socket
	if ((master = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("[-] Could not create socket : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
}

void prepare_socket()
{
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(DEFAULT_PORT);
}

void bind_server()
{
	//Bind
	if (bind(master, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR)
	{
		printf("[-] Bind failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	puts("[*] Bind done\r\n");

	//Listen to incoming connections
	listen(master, 3);
}

void init_socket_fd()
{
	int i;
	//clear the socket fd set
	FD_ZERO(&readfds);

	//add master socket to fd set
	FD_SET(master, &readfds);

	//add child sockets to fd set
	for (i = 0; i < MAX_CLIENTS; i++)
	{
		s = client_socket[i];
		if (s > 0)
		{
			FD_SET(s, &readfds);
		}
	}
}

void start_listeners()
{
	//wait for an activity on any of the sockets, timeout is NULL , so wait indefinitely
	int activity = select(0, &readfds, NULL, NULL, NULL);

	if (activity == SOCKET_ERROR)
	{
		printf("[-] select call failed with error code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
}

void acept_new_connection()
{
	int i;
	SOCKET new_socket;	
	char *message = "Welcome to VulChat v0.0.1\r\n\n>";
	char ip_address[INET_ADDRSTRLEN];
	addrlen = sizeof(struct sockaddr_in);

	//If something happened on the master socket, then its an incoming connection
	if (FD_ISSET(master, &readfds))
	{
		if ((new_socket = accept(master, (struct sockaddr *)&address, (int *)&addrlen))<0)
		{
			perror("accept");
			exit(EXIT_FAILURE);
		}

		//inform user of socket number - used in send and receive commands	
		inet_ntop(AF_INET, &(address.sin_addr), ip_address, INET_ADDRSTRLEN);
		printf("[*] New connection, socket fd is %d, ip is: %s, port : %d \n", new_socket, ip_address, ntohs(address.sin_port));

		//send new connection greeting message
		if (send(new_socket, message, strlen(message), 0) != strlen(message))
		{
			perror("[-] send failed");
		}
		
		//add new socket to array of sockets
		for (i = 0; i < MAX_CLIENTS; i++)
		{
			if (client_socket[i] == 0)
			{
				client_socket[i] = new_socket;
				printf("[*] Adding to list of sockets at index %d \n", i);
				break;
			}
		}
	}
}

//This function has a buffer overflow vulnerability 
void vul_cmd_proccess(int s, char *buffer, int client)
{
	char cmd[20]; //vuln params
	char *msg = "bad command\r\n";
	int length = 10;

	strcpy(cmd, buffer);
	if (strlen(buffer) < 20)
	{
		length = strlen(buffer);
	}

	cmd[length] = '\0';

	//cmd [register "name_user", list, send (name_user) "text"]
	if (0 == strcmp(cmd, "hello"))
	{
		msg = "good command\r\n";
	}
	else if (0 == strcmp(cmd, "quit"))
	{
		getpeername(s, (struct sockaddr*)&address, (int*)&addrlen);
		inet_ntop(AF_INET, &(address.sin_addr), ip_address, INET_ADDRSTRLEN);
		printf("[-] Host close the connection, ip %s, port %d \n", ip_address, ntohs(address.sin_port));

		closesocket(s);
		client_socket[client] = 0;
		return;
	}

	send(s, msg, strlen(msg), 0);
}

void waiting_connections()
{
	int client, valread, enter_cmd, length;		

	//1 extra for null character, string termination
	char *buffer, *buffer_recv;
	buffer = (char*)malloc((MAXRECV + 1) * sizeof(char));
	buffer_recv = (char*)malloc((MAXRECV + 1) * sizeof(char));
	//Accept and incoming connection
	puts("Waiting for incoming connections...\n");

	while (TRUE)
	{
		init_socket_fd();
		start_listeners();

		acept_new_connection();

		//else its some IO operation on some other socket :)
		for (client = 0; client < MAX_CLIENTS; client++)
		{
			s = client_socket[client];
			//if client presend in read sockets            
			if (FD_ISSET(s, &readfds))
			{
				//get details of the client
				getpeername(s, (struct sockaddr*)&address, (int*)&addrlen);
				inet_ntop(AF_INET, &(address.sin_addr), ip_address, INET_ADDRSTRLEN);
				//Check if it was for closing , and also read the incoming message
				//recv does not place a null terminator at the end of the string (whilst printf %s assumes there is one).
				enter_cmd = 1;
				length = 0;
				do 
				{
					valread = recv(s, buffer_recv, MAXRECV, 0);
					if (valread == SOCKET_ERROR)
					{
						int error_code = WSAGetLastError();
						if (error_code == WSAECONNRESET)
						{
							//Somebody disconnected , get his details and print
							printf("[-] Host disconnected unexpectedly , ip %s , port %d \n", ip_address, ntohs(address.sin_port));

							//Close the socket and mark as 0 in list for reuse
							closesocket(s);
							client_socket[client] = 0;
						}
						else
						{
							printf("[-] recv failed with error code : %d\n", error_code);
						}

						enter_cmd = 0;
						break;
					}
					if (valread == 0)
					{
						//Somebody disconnected , get his details and print					
						printf("[-] Host disconnected, ip %s, port %d \n", ip_address, ntohs(address.sin_port));

						//Close the socket and mark as 0 in list for reuse
						closesocket(s);
						client_socket[client] = 0;

						enter_cmd = 0;
						break;
					}

					memcpy(&(buffer[length]), buffer_recv, valread);
					length += valread;
				} 
				while (buffer_recv[0] != '\r' || buffer_recv[1] != '\n');
				
				if (enter_cmd)
				{				
					buffer[length - 2] = '\0';
					vul_cmd_proccess(s, buffer, client);
				}
			}
		}
	}
}

int main(int argc, char* argv[])
{	
	init_client_socket();

	init_wind_socket();	
	printf("[*] Initialised.\n");

	create_socket();
	printf("[*] Socket created.\n");

	prepare_socket();

	printf("[*] Running at %d port.\n", DEFAULT_PORT);

	bind_server();

	waiting_connections();

	closesocket(s);
	WSACleanup();

	return 0;
}

