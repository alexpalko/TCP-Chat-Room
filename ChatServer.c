#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /* for sockets */
#include <sys/types.h>
#include <arpa/inet.h> /* for addresses */
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_CLIENTS 50
#define USER_NAME_LENGTH 32
#define RECV_BUF_SIZE 1024
#define SEND_BUF_SIZE 1058

typedef struct client {
	int socket;
	struct sockaddr_in addr;
	char userName[32];
	pthread_t tid;
}client_t;

int clientCounter = 0;
client_t *clients[MAX_CLIENTS];

void exitWithError(char *msg){
	perror(msg);
	exit(1);
}

void deleteClient(int id){
	pthread_t tid = clients[id]->tid;
	if(close(clients[id]->socket) < 0)
		exitWithError("close() error in deleteClient()");
	free(clients[id]);
	clients[id] = NULL;
	clientCounter--;
	
	pthread_join(tid, NULL);
}

#define SEND_BUF_SIZE_PVT SEND_BUF_SIZE + 16

pthread_mutex_t mutex;

void privateMessage(int id){
	char recvUserName[USER_NAME_LENGTH + 1];
	char recvMsgBuf[RECV_BUF_SIZE + 1];
	char sendMsgBuf[SEND_BUF_SIZE + 1];
	int validUserName = 0; 
	int recvUserNameLen;
	int recvMsgBufLen;
	int sendMsgBufLen;
	int i;
	
	if((recvUserNameLen = recv(clients[id]->socket, recvUserName, USER_NAME_LENGTH, 0)) < 0)
		exitWithError("recv() error at user name in privateMessage()");
	
	recvUserName[recvUserNameLen] = '\0';
	for(i = 0; i < clientCounter; i++)
		if(clients[i] != NULL && !strcmp(clients[i]->userName, recvUserName)){
			validUserName = 1;
			break;
		}
		
	pthread_mutex_lock(&mutex);
	if(send(clients[id]->socket, &validUserName, 4, 0) != 4)
		exitWithError("send() error at user name confirmation in privateMessage()");
	pthread_mutex_unlock(&mutex);
	
	if(!validUserName)
		return;
	
	if((recvMsgBufLen = recv(clients[id]->socket, recvMsgBuf, RECV_BUF_SIZE, 0)) < 0)
		exitWithError("recv() error at buf recv in privateMessage()");
	
	recvMsgBuf[recvMsgBufLen] = '\0';
	
	if(recvMsgBuf[0] == '\n')
			return;
	
	strcpy(sendMsgBuf, clients[id]->userName);
	strcat(sendMsgBuf, " private message: ");
	strcat(sendMsgBuf, recvMsgBuf);
	sendMsgBufLen = strlen(sendMsgBuf);
	printf("%s private message to %s: %s", clients[id]->userName, clients[i]->userName, recvMsgBuf);
	
	if(send(clients[i]->socket, sendMsgBuf, sendMsgBufLen, 0) != sendMsgBufLen)
		exitWithError("send() error at message in privateMessage()");

}

void listUsers(int id){
	if(send(clients[id]->socket, "Users online:\n", strlen("Users online:\n"), 0) != strlen("Users online:\n"))
		exitWithError("send() error at listUsers()");
	
	char msgBuf[USER_NAME_LENGTH + 2];
	int msgLen;
	
	for(int i = 0; i < clientCounter; i++)
		if(clients[i] != NULL){
			strcpy(msgBuf, clients[i]->userName);
			strcat(msgBuf, "\n");
			msgLen = strlen(msgBuf);
			if(send(clients[id]->socket, msgBuf, msgLen, 0) != msgLen)
				exitWithError("send() error at listUsers()");
		}
}

void listCommads(int id){
	char *msgBuf = "List of commands:\n"
				   "    * /pm - send a private message to certain users\n"
				   "    * /u - get a list of all users in the server\n"
				   "    * /h - get a list of all commands\n";
	int msgLen = strlen(msgBuf);
	
	if(send(clients[id]->socket, msgBuf, msgLen, 0) != msgLen)
		exitWithError("send() error at listCommads()");
}

void clientHandler(int id){
	char recvMsgBuf[RECV_BUF_SIZE + 1];
	char sendMsgBuf[SEND_BUF_SIZE + 1];
	int recvMsgSize;
	int sendMsgSize;
	
	printf("Client %s:%d chose user name: %s\n", inet_ntoa(clients[id]->addr.sin_addr), ntohs(clients[id]->addr.sin_port), clients[id]->userName);
	
	strcpy(sendMsgBuf, clients[id]->userName);
	strcat(sendMsgBuf, " has connected.\n");
	sendMsgSize = strlen(sendMsgBuf);
	for(int i = 0; i < MAX_CLIENTS; i++)
			if(i != id && clients[i] != NULL) 
				if(send(clients[i]->socket, sendMsgBuf, sendMsgSize, 0) < sendMsgSize)
					exitWithError("send() error at userName in  clientHandler()");
	
	while((recvMsgSize = recv(clients[id]->socket, recvMsgBuf, RECV_BUF_SIZE, 0)) > 0){
		if(recvMsgBuf[0] == '/'){
			if(!strncmp(recvMsgBuf, "/pm\n", 4)){ 
				printf("%s requested to send a private message.\n", clients[id]->userName);
				privateMessage(id);
				continue;
			}
			if(!strncmp(recvMsgBuf, "/u\n", 3)){
				printf("%s requested the list of users online.\n", clients[id]->userName);
				listUsers(id);
				continue;
			}
			if(!strncmp(recvMsgBuf, "/h\n", 3)){
				printf("%s requested the list of commands.\n", clients[id]->userName);
				listCommads(id);
				continue;
			}
			if(send(clients[id]->socket, "Invalid command.\n", strlen("Invalid command.\n"), 0) != strlen("Invalid command.\n"))
				exitWithError("send() error at clientHandler()");
			memset(recvMsgBuf, '\0', RECV_BUF_SIZE + 1);
			continue;
		}
		
		// No point in printing an empty line
		if(recvMsgBuf[0] == '\n')
			continue;
		
		strcpy(sendMsgBuf, clients[id]->userName);
		strcat(sendMsgBuf, ": ");
		strcat(sendMsgBuf, recvMsgBuf);
		printf("%s", sendMsgBuf);
		sendMsgSize = strlen(sendMsgBuf);
		
		for(int i = 0; i < MAX_CLIENTS; i++)
			if(i != id && clients[i] != NULL) 
				if(send(clients[i]->socket, sendMsgBuf, sendMsgSize, 0) != sendMsgSize)
					exitWithError("send() error at clientHandler()");
		
		memset(recvMsgBuf, '\0', RECV_BUF_SIZE + 1);
	}
	
	if((recvMsgSize = recv(clients[id]->socket, recvMsgBuf, RECV_BUF_SIZE, 0)) < 0)
			exitWithError("recv() error at message in clientHandler()");
	
	if(close(clients[id]->socket) < 0)
		exitWithError("close() error");
	
	deleteClient(id);
}
char *getUserName(int clientSocket){
	static char userName[USER_NAME_LENGTH + 1];
	int userNameSize;
	
	int validUserName = 0;
	while(!validUserName){
		if((userNameSize = recv(clientSocket, userName, USER_NAME_LENGTH, 0)) < 0)
		exitWithError("recv() error at getUserName()");
		userName[userNameSize] = '\0';
		
		validUserName = 1;
		for(int i = 0; i  < clientCounter && validUserName; i++)
			if(clients[i] != NULL && !strcmp(userName, clients[i]->userName))
				validUserName = 0;
			
		if(send(clientSocket, &validUserName, 4, 0) != 4)
			exitWithError("send() error at getUserName()");
	}
	
	return userName;
}

void createClient(void * voidNewClient){	
	client_t *newClient = (client_t *) voidNewClient;
	int i;
	strcpy(newClient->userName, getUserName(newClient->socket));
	
	clientCounter++;
	
	for(i = 0; i < MAX_CLIENTS; i++)
		if(clients[i] == NULL)
			break;
	
	clients[i] = newClient;
	clientHandler(i);
}
int main(){

	int serverSocket, clientSocket;
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t clientAddrSize = sizeof(clientAddr);

	if(pthread_mutex_init(&mutex, NULL) < 0)
		exitWithError("pthread_mutex_init() error");
	
	if((serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		exitWithError("socket() error at serverSocket");
	
	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(5501);
	
	if(bind(serverSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0)
		exitWithError("bind() error");
	
	if(listen(serverSocket, MAX_CLIENTS) < 0)
		exitWithError("listen() error");
	printf("Server %s:%d\n", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port));
	while(1){
		
		if((clientSocket = accept(serverSocket, (struct sockaddr *) &clientAddr,
									&clientAddrSize)) < 0)
			exitWithError("accept() error");

		if(clientCounter == MAX_CLIENTS){
			printf("A user is trying to connect, but the server is full.\n");
			fflush(stdout);
			continue;
		}
		
		printf("Handling client %s:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
		
		client_t *newClient = (client_t *)malloc(sizeof(client_t));
		newClient->socket = clientSocket;
		newClient->addr = clientAddr;
		pthread_create(&newClient->tid, NULL, (void *) createClient, (void *) newClient);
	}
	pthread_mutex_destroy(&mutex);
	return 0;
}