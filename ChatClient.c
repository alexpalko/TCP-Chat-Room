#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#define USER_NAME_LENGTH 32
#define RECV_MSG_SIZE 1056
#define SEND_MSG_SIZE 1024

pthread_mutex_t mutex;

void exitWithError(char *msg){
	perror(msg);
	exit(1);
}

void messageReceiver(void *voidClientSocket){
	int clientSocket = *(int *)voidClientSocket;
	char recvBuf[RECV_MSG_SIZE + 1];
	int	recvBufLen;
	
	while((recvBufLen = recv(clientSocket, recvBuf, RECV_MSG_SIZE, 0)) > 0){
		recvBuf[recvBufLen] = '\0';
		printf("%s", recvBuf);
	}
	
	if(recvBufLen < 0)
		exitWithError("recv() error at messageReceiver");
}

int main(){
	int clientSocket; 
	struct sockaddr_in clientAddress;
	char userName[USER_NAME_LENGTH + 1];
	char msgBuf[SEND_MSG_SIZE + 1];
	int msgBufLen;
	
	if(pthread_mutex_init(&mutex, NULL) < 0)
		exitWithError("pthread_mutex_init() error");
	
	if((clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		exitWithError("socket() error");
	
	memset(&clientAddress, 0, sizeof(clientAddress));
	clientAddress.sin_family = AF_INET;
	clientAddress.sin_addr.s_addr = inet_addr("0.0.0.0");
	clientAddress.sin_port = htons((unsigned short)5501);
	
	if(connect(clientSocket, (struct sockaddr *) &clientAddress, sizeof(clientAddress)) < 0)
		exitWithError("connect() error");
	
	// Reading the user name form the user
	int validName = 0;
	while(!validName){
		printf("Choose a userName: ");
		scanf("%32s", userName);
	
		// Sending the user name to the server
		if(send(clientSocket, userName, strlen(userName), 0) != strlen(userName))
			exitWithError("send() error at user name");
		
		if(recv(clientSocket, &validName, 4, 0) < 0)
			exitWithError("recv() error at user name");
		
		if(!validName)
			printf("Invalid user name, try again.\n");
	}
	pthread_t tid;
	pthread_create(&tid, NULL, (void *)messageReceiver, (void *) &clientSocket);
	
	fgets(msgBuf, SEND_MSG_SIZE, stdin);
	
	while(msgBuf[0] != '*'){
		msgBufLen = strlen(msgBuf);
		if(msgBuf[msgBufLen - 1] != '\n'){
			printf("Message it too long, maximum %d characters allowed.\n", SEND_MSG_SIZE - 1);
			while(getchar() != '\n');
		}
		else
		if(msgBufLen && send(clientSocket, msgBuf, msgBufLen, 0) != msgBufLen)
			exitWithError("send() error");
		
		if(msgBuf[0] == '/'){
			if(!strncmp(msgBuf, "/pm\n", 4)){
				char userName[USER_NAME_LENGTH];
				int userNameLen;
				
				pthread_mutex_lock(&mutex);

				printf("Choose user to send message to: ");
				//fflush(stdout);
				fgets(userName, USER_NAME_LENGTH, stdin);
				userNameLen  = strlen(userName);
				
				if(userName[userNameLen - 1] != '\n'){
					printf("Not a valid user name, type \"/u\" to get a list of users.\n");
					while(getchar() != '\n');
				}
				else // exclude '\n'
					userName[userNameLen - 1] = '\0';
				
				userNameLen--;
				
				if(send(clientSocket, userName, userNameLen, 0) != userNameLen)
					exitWithError("send() error at user name for private message");
				
				int validUser;
				
				if(recv(clientSocket, &validUser, 4, 0) < 0)
					exitWithError("recv() error at user name for private message");

				if(validUser){
					printf("Message for %s: ", userName);
					fgets(msgBuf, SEND_MSG_SIZE, stdin);
					msgBufLen = strlen(msgBuf);
					if(msgBuf[msgBufLen - 1] != '\n'){
						printf("Message it too long, maximum %d characters allowed.\n", SEND_MSG_SIZE - 1);
						while(getchar() != '\n');
					}
					else
						if(msgBufLen && send(clientSocket, msgBuf, msgBufLen, 0) != msgBufLen)
							exitWithError("send() error");
				}
				else
					printf("User %s was not found, type \"/u\" to get a list of users.\n", msgBuf);
				
				pthread_mutex_unlock(&mutex);
			}
		}
		
		msgBuf[0] = '\0';
	
		fgets(msgBuf, SEND_MSG_SIZE, stdin);
	}
	
	pthread_cancel(tid);
	
	pthread_mutex_destroy(&mutex);
	
	close(clientSocket);
	
	return 0;
}