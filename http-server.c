#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

void* handle_http_request(void* sockaddr)
{
	int sock = *(int*)sockaddr;
	free(sockaddr);
	const char* response200="HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\n";
	const char* response206="HTTP/1.1 206 Partial Content\r\nConnection: Keep-Alive\r\n";
	const char* response404="HTTP/1.1 404 NOT FOUND\r\n\r\n";
	char buf[1024] = {0};
	errno = 0;
	int bytes = read(sock,buf,sizeof(buf));
	if(bytes < 0){
		perror("http read failed!");
		exit(1);
	}
		//printf("%s\n",buf);
		char path[100];
		int i=0;
		//analysis path of buf
		while(buf[i++]!=' ');
		if(buf[i]=='h'){
			int cnt=3;
			while (cnt>0)
			{
				if(buf[i++]=='/')
					cnt--;
			}
		}else{
			if(buf[i]=='/')
				i++;
		}
		//copy path
		int j=0;
		while(buf[i]!=' '){
			path[j++]=buf[i++];
		}
		path[j]='\0';
		//search for range
		while(buf[i]!='R' && buf[i]!='\0'){
			i++;
		}
		//test path
		FILE* fp=fopen(path,"r");
		if(fp==NULL){
			send(sock,response404,strlen(response404),0);
		}else
		{	
			int begin=0,end=-1,range = 0;
			if(buf[i++]=='R' && buf[i++]=='a' && buf[i++]=='n' && buf[i++]=='g' && buf[i++]=='e'){
				range = 1;
				while(buf[i++]!='=');
				while (buf[i]!='-')
				{
					begin=begin*10+buf[i++]-'0';
				}
				printf("begin = %d\n",begin);

				i++;
				while (buf[i]<='9' && buf[i]>='0')
				{
					if(end<0)
						end=0;
					end = end * 10 + buf[i++]-'0';
				}
				printf("end =%d\n",end);
			}
			struct stat sbuf;
			stat(path, &sbuf);
			long size = 0;
			if(end>0){
				size = end - begin + 1;
			}else{
				size = sbuf.st_size - begin;
			}
			if(range){
				char buf206[200]={0};
				sprintf(buf206,"%sContent-length: %ld\r\n\r\n",response206,size);
				send(sock, buf206, strlen(buf206),0);
				// send(sock, response206, strlen(response206),0);
			}else{
				char buf200[200]={0};
				sprintf(buf200,"%sContent-length: %ld\r\n\r\n",response200,size);
				send(sock, buf200, strlen(buf200),0);
				// send(sock, response200, strlen(response200),0);
			}
			fseek(fp,begin,SEEK_SET);
			char *srcp = (char *)malloc(size+100);
			size = fread(srcp,1,size,fp);
			printf("[DEBUG] send %ld of bytes\n",size);
			send(sock,srcp,size,0);
			free(srcp);
			fclose(fp);
		}
	// return 301
	// char response[1024]="HTTP/1.1 301 Moved Permanently\r\nLocation: https://10.0.0.1";
	// char buf[1024]={0};
	// int bytes = read(sock,buf,sizeof(buf));
	// if(bytes < 0){
	// 	perror("http read failed!");
	// 	exit(1);
	// }else{
	// 	//search for url
	// 	int i=0,j=0;
	// 	while(buf[i++]!=' ');
	// 	while(response[j]!='\0'){
	// 		j++;
	// 	}
	// 	while (buf[i]!=' ')
	// 	{
	// 		response[j++]=buf[i++];
	// 	}
	// 	response[j++]='\r';
	// 	response[j++]='\n';
	// 	response[j++]='\r';
	// 	response[j++]='\n';

	// 	if(send(sock,response,strlen(response),0)<0)
	// 		printf("send %s at %d error!\n",response,sock);
	// 	//else
	// 		//printf("send %s at %d already!\n",response,sock);
	// }
	printf("[DEBUG] close sock here\n");
	close(sock);
	return NULL;
}

void* handle_https_request(void* ssladdr){
	const char* response200="HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\n";
	const char* response206="HTTP/1.1 206 Partial Content\r\nConnection: Keep-Alive\r\n";
	const char* response404="HTTP/1.1 404 NOT FOUND\r\n\r\n";
	SSL* ssl=(SSL*)ssladdr;
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else {
		char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
		//printf("%s\n",buf);
		char path[100];
		int i=0;
		//analysis path of buf
		while(buf[i++]!=' ');
		if(buf[i]=='h'){
			int cnt=3;
			while (cnt>0)
			{
				if(buf[i++]=='/')
					cnt--;
			}
		}else{
			if(buf[i]=='/')
				i++;
		}
		//copy path
		int j=0;
		while(buf[i]!=' '){
			path[j++]=buf[i++];
		}
		path[j]='\0';
		//search for range
		while(buf[i]!='R' && buf[i]!='\0'){
			i++;
		}

		//test path
		FILE* fp=fopen(path,"r");
		if(fp==NULL){
			SSL_write(ssl,response404,strlen(response404));
		}else
		{	
			int begin=0,end=-1,range = 0;
			if(buf[i++]=='R' && buf[i++]=='a' && buf[i++]=='n' && buf[i++]=='g' && buf[i++]=='e'){
				range = 1;
				while(buf[i++]!='=');
				while (buf[i]!='-')
				{
					begin=begin*10+buf[i++]-'0';
				}
				//printf("begin = %d",begin);

				i++;
				while (buf[i]<='9' && buf[i]>='0')
				{
					if(end<0)
						end=0;
					end = end * 10 + buf[i++]-'0';
				}
				//printf("end =%d\n",end);
			}
			if(range)
				SSL_write(ssl, response206, strlen(response206));
			else
				SSL_write(ssl, response200, strlen(response200));
			struct stat sbuf;
			stat(path, &sbuf);
			long size = 0;
			if(end>0){
				size = end - begin;
			}else{
				size = sbuf.st_size - begin;
			}
			if(range){
				char buf206[200]={0};
				sprintf(buf206,"%sContent-length: %ld\r\n\r\n",response206,size);
				SSL_write(ssl,buf206,strlen(buf206));
			}else{
				char buf200[200]={0};
				sprintf(buf200,"%sContent-length: %ld\r\n\r\n",response200,size);
				SSL_write(ssl, buf200, strlen(buf200));
			}
			fseek(fp,begin,SEEK_SET);
			char *srcp = (char *)malloc(size+100);
			size = fread(srcp,1,size,fp);
			printf("[DEBUG] send %ld of bytes\n",size);
			SSL_write(ssl,srcp,size);
			free(srcp);
			fclose(fp);
		}
    }
    int sock = SSL_get_fd(ssl);
	//printf("https sock = %d",sock);
    SSL_free(ssl);
    close(sock);
	return NULL;
}

void* http_thread(){
	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(80);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

    while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		printf("[DEBUG] before accept\n");
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);//blocked when no request
		if (csock < 0) {
			printf("[DEBUG] no more accept!\n");
			perror("Accept failed");
			exit(1);
		}else{
			printf("[DEBUG] accept csock %d, sock %d\n", csock, sock);
		}
		//handle_http_request
		int* http_sock=(int *)malloc(sizeof(int));
		*http_sock = csock;
		pthread_t handle;
		pthread_create(&handle,NULL,handle_http_request,(void *)http_sock);
	}
	printf("[DEBUG] close sock %d\n", sock);
	close(sock);

	return NULL;
}

void* https_thread(){
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method); // create a new SSL_CTX object as framework for TLS/SSL enabled functions

	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}

	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(443);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		SSL *ssl = SSL_new(ctx);
		SSL_set_fd(ssl, csock);
		pthread_t request;
		pthread_create(&request,NULL,handle_https_request,(void*)ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);
}

int main()
{
    pthread_t http,https;
	void *http_result, *https_result;
    pthread_create(&http,NULL,http_thread,NULL);
	pthread_create(&https,NULL,https_thread,NULL);
	pthread_join(http,&http_result);
	pthread_join(https,&https_result);

	return 0;
}
