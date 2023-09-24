#pragma once

#include "header.h"
#include "default.h"
#include "system.h"

char IPAddr[MAX_SIZE];
char domain[MAX_SIZE];

/* �ֵ����ṹ�� */
typedef struct trie_node {
	uint16_t pre;			// �������
	uint16_t val[37];		// ��ȡ�����е�ÿ���ַ��ı��num����val[num]��Ŷ���ĳ�ַ�ʱ���ý��ı��
	uint8_t IP[4];			// ʮ����IP��ַ
	uint8_t isEnd;			// �Ƿ�Ϊһ�������Ľ���
} trie;

/* LRU����ṹ�� */
typedef struct node {
	uint8_t IP[4];
	char domain[MAX_SIZE];
	struct node* next;
} lru_node;

typedef struct {
	uint16_t client_ID;
	int expire_time; // ����ʱ��
	struct sockaddr_in client_addr;
} ID_conversion;

ID_conversion ID_list[ID_LIST_SIZE]; // IDת��

trie list_trie[MAX_NUM];	// �洢������Ϣ���ֵ���
lru_node* head;
lru_node* tail;
int list_size;
int cache_size;

/* ��ȡ�ַ�����ʽ��IPv4��ַ��ת������������ */
void transfer_IP(uint8_t* this_IP, char* IP_addr);

/* ���������ַ�ת�ɶ�Ӧ��ֵ */
int get_num(uint8_t val);

/* ���ӡ���ѯ�ֵ������ */
void add_node(trie* root, uint8_t* IP, char* domain);
int query_node(trie* root, char* domain, uint8_t* ip_addr);

/* ��ʼ������ */
void init_cache();

/* �ӻ��������в�ѯ */
int query_cache(char* domain, uint8_t* ip_addr);

/* ���»������� */
void update_cache(uint8_t ip_addr[4], char* domain);

/* ɾ����Զδʹ�ý�� */
void delete_cache();

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr);
