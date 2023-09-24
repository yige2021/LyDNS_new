#pragma once

#include "header.h"
#include "default.h"
#include "system.h"

char IPAddr[MAX_SIZE];
char domain[MAX_SIZE];

/* 字典树结构体 */
typedef struct trie_node {
	uint16_t pre;			// 父结点编号
	uint16_t val[37];		// 读取域名中的每个字符的编号num，则val[num]存放读入某字符时，该结点的编号
	uint8_t IP[4];			// 十进制IP地址
	uint8_t isEnd;			// 是否为一个域名的结束
} trie;

/* LRU链表结构体 */
typedef struct node {
	uint8_t IP[4];
	char domain[MAX_SIZE];
	struct node* next;
} lru_node;

typedef struct {
	uint16_t client_ID;
	int expire_time; // 过期时间
	struct sockaddr_in client_addr;
} ID_conversion;

ID_conversion ID_list[ID_LIST_SIZE]; // ID转换

trie list_trie[MAX_NUM];	// 存储域名信息的字典树
lru_node* head;
lru_node* tail;
int list_size;
int cache_size;

/* 提取字符串形式的IPv4地址，转到整数数组里 */
void transfer_IP(uint8_t* this_IP, char* IP_addr);

/* 把域名中字符转成对应的值 */
int get_num(uint8_t val);

/* 增加、查询字典树结点 */
void add_node(trie* root, uint8_t* IP, char* domain);
int query_node(trie* root, char* domain, uint8_t* ip_addr);

/* 初始化缓存 */
void init_cache();

/* 从缓存链表中查询 */
int query_cache(char* domain, uint8_t* ip_addr);

/* 更新缓存链表 */
void update_cache(uint8_t ip_addr[4], char* domain);

/* 删除最远未使用结点 */
void delete_cache();

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr);
