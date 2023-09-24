#pragma once

#include "header.h"
#include "default.h"
#include "data_struct.h"
#include "dns_struct.h"
#include "system.h"

int mode;					// 阻塞/非阻塞模式
int client_sock;			// 客户端socket
int server_sock;			// 服务端socket
struct sockaddr_in client_addr;
struct sockaddr_in server_addr;
int addr_len;

int client_port;			// 客户端端口号
char* remote_dns;			// 远程主机（BUPT的DNS服务器）

int is_listen;

void init_socket();
void close_server();
void nonblock();
void block();
void receive_client();
void receive_server();
