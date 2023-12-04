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

void* handle_http_request(void* sockaddr)
{
	int sock = *(int*)sockaddr;
	free(sockaddr);
	char response[1024]="HTTP/1.0 301 Moved Permanently\r\nLocation: https://10.0.0.1";
	char buf[1024]={0};
	int bytes = read(sock,buf,sizeof(buf));
	if(bytes < 0){
		perror("http read failed!");
		exit(1);
	}else{
		//search for url
		int i=0,j=0;
		while(buf[i++]!=' ');
		while(response[j]!='\0'){
			j++;
		}
		while (buf[i]!=' ')
		{
			response[j++]=buf[i++];
		}
		response[j++]='\r';
		response[j++]='\n';
		response[j++]='\r';
		response[j++]='\n';

		if(send(sock,response,strlen(response),0)<0)
			printf("send %s at %d error!\n",response,sock);
		//else
			//printf("send %s at %d already!\n",response,sock);
	}
	close(sock);
	return NULL;
}

void* handle_https_request(void* ssladdr){
    const char* response200="HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
	const char* response206="HTTP/1.0 206 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
	const char* response404="HTTP/1.0 404 NOT FOUND\r\n\r\n";
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
		//printf("%s\n",path);

		//search for range
		while(buf[i]!='R' && buf[i]!='\0'){
			i++;
		}
		//printf("after search 'R'");
		
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

			int num;
			buf[2]='\r';
			buf[3]='\n';
			fseek(fp,begin,SEEK_SET);
			if(end > 0 )
				end = end - begin + 1;
				//end = end - begin;
			while((num = fread(&buf[4],1,255,fp)) > 0 && end != 0){
				//规范分块传输格式
				int i;
				if(end>0){
					if(end<num){
						num = end;
						end = 0;
					}else
						end -=num;
				}
				i=num/16;
				buf[0] = i>9? i + 'A' - 10 : i + '0';
				i=num%16;
				buf[1] = i>9? i + 'A' - 10 : i + '0';
				buf[num+4]='\r';
				buf[num+5]='\n';
				//printf("send one pakage size of %x\n",num);
				SSL_write(ssl,buf,num+6);
			}
			fclose(fp);
			SSL_write(ssl,"0\r\n",3);
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
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);//blocked when no request
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		//handle_http_request
		int* http_sock=(int *)malloc(sizeof(int));
		*http_sock = csock;
		pthread_t handle;
		pthread_create(&handle,NULL,handle_http_request,(void *)http_sock);
	}

	close(sock);

	return NULL;
}

int main()
{
    pthread_t http;
    pthread_create(&http,NULL,http_thread,NULL);
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
		//printf("csock = %d\n",csock);
		pthread_t request;
		pthread_create(&request,NULL,handle_https_request,(void*)ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);

	return 0;
}
