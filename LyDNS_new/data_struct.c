#include "data_struct.h"

ID_conversion ID_list[ID_LIST_SIZE];

trie list_trie[MAX_NUM];
int list_size = 0;
int cache_size = 0;

lru_node* head;
lru_node* tail;

void transfer_IP(uint8_t* this_IP, char* IP_addr) {
    int len = strlen(IP_addr);
    int i;
    int tmp = 0;
    int IP_pos = 0;
    char* ptr = IP_addr;

    for (i = 0; i < len; i++) {
        if (*ptr != '.') {
            tmp = tmp * 10 + (*ptr - '0');
        }
        else {
            this_IP[IP_pos++] = tmp;
            tmp = 0;
        }
        ptr++;
    }

    this_IP[3] = tmp;
}

int get_num(uint8_t val) {
    /* num的取值范围：
    * 0~9：数字0~9
    * 10~35：字母a~z，不分大小写
    * 36：连词号'-'
    * 37：点号
    */
    int num;

    if (val >= '0' && val <= '9') {
        num = val - '0';
    }
    else if (val >= 'a' && val <= 'z') {
        num = val - 'a' + 10;
    }

    else if (val >= 'A' && val <= 'Z') {
        num = val - 'A' + 10;
    }

    else if (val == '-') {
        num = 36;
    }

    else if (val == '.') {
        num = 37;
    }
    return num;
}

void add_node(trie* root, uint8_t* IP, char* domain) {
    int i;
    int len = strlen(domain);
    int index = 0;

    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {
            list_trie[index].val[num] = ++list_size;
        }
        list_trie[list_trie[index].val[num]].pre = index;
        index = list_trie[index].val[num];
    }

    for (i = 0; i < 4; i++) {
        list_trie[index].IP[i] = IP[i];
    }

    list_trie[index].isEnd = 1;
}

int query_node(trie* root, char* domain, uint8_t* ip_addr) {
    int i;
    int len = strlen(domain);
    int index = 0;

    for (i = 0; i < len; i++) {
        int num = get_num(domain[i]);

        if (list_trie[index].val[num] == 0) {

            if (debug_mode == 1) {
                printf("Address not found in hosts.\n");
            }

            return 0;
        }

        index = list_trie[index].val[num];
    }

    if (list_trie[index].isEnd == 0) {

        if (debug_mode == 1) {
            printf("Address not found in hosts.\n");
        }

        return 0;
    }

    if (debug_mode == 1) {
        printf("Address found in hosts: ");
        for (i = 0; i < 3; i++) {
            printf("%d.", list_trie[index].IP[i]);
        }
        printf("%d\n", list_trie[index].IP[3]);
    }

    update_cache(list_trie[index].IP, domain);
    memcpy(ip_addr, list_trie[index].IP, 4);

    return 1;
}

void init_ID_list() {
    for (int i = 0; i < ID_LIST_SIZE; i++)
    {
        ID_list[i].client_ID = 0;
        ID_list[i].expire_time = 0;
        memset(&(ID_list[i].client_addr), 0, sizeof(struct sockaddr_in));
    }
}

void init_cache() {
    /* 初始化LRU链表 */
    head = malloc(sizeof(struct node));
    head->next = NULL;
    tail = head;
}

int query_cache(char* domain, uint8_t* ip_addr) {
    lru_node* ptr = head;

    /* 先查找缓存中是否已存在域名，若存在则将其放到头部 */
    while (ptr->next) {
        if (strcmp(ptr->next->domain, domain) == 0) {

            if (debug_mode == 1) {
                printf("Address found in cache: ");
                printf("%d %d %d %d\n", ptr->next->IP[0], ptr->next->IP[1], ptr->next->IP[2], ptr->next->IP[3]);
            }

            memcpy(ip_addr, ptr->next->IP, sizeof(ptr->next->IP));
            lru_node* tar = ptr->next;
            ptr->next = tar->next;
            tar->next = head->next;
            head->next = tar;
            return 1;
        }
        else {
            ptr = ptr->next;
        }
    }
    return 0;
}

void update_cache(uint8_t ip_addr[4], char* domain) {
    lru_node* newNode = malloc(sizeof(lru_node));

    if (cache_size > MAX_CACHE) {
        delete_cache();
    }

    cache_size++;

    memcpy(newNode->IP, ip_addr, sizeof(uint8_t) * 4);
    memcpy(newNode->domain, domain, strlen(domain) + 1);
    newNode->next = head->next;
    head->next = newNode;
}

void delete_cache() {
    lru_node* p = head;
    while (p->next) {
        if (p->next->next == NULL) {
            tail = p->next;
            p->next = NULL;
            free(tail);
            return;
        }
        p = p->next;
    }
}

uint16_t set_ID(uint16_t client_ID, struct sockaddr_in client_addr) {
    uint16_t i;
    for (i = 0; i < ID_LIST_SIZE; i++) {
        if (ID_list[i].expire_time < time(NULL)) {
            ID_list[i].client_ID = client_ID;
            ID_list[i].client_addr = client_addr;
            ID_list[i].expire_time = ID_EXPIRE_TIME + time(NULL); // 预期过期时间
        }
        break;
    }
    return i;
}