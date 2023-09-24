#pragma once

#include "header.h"
#include "default.h"
#include "data_struct.h"
#include "dns_struct.h"
#include "system.h"

int mode;					// ����/������ģʽ
int client_sock;			// �ͻ���socket
int server_sock;			// �����socket
struct sockaddr_in client_addr;
struct sockaddr_in server_addr;
int addr_len;

int client_port;			// �ͻ��˶˿ں�
char* remote_dns;			// Զ��������BUPT��DNS��������

int is_listen;

void init_socket();
void close_server();
void nonblock();
void block();
void receive_client();
void receive_server();
