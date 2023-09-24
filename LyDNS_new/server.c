#include "server.h"

int client_port;
int addr_len = sizeof(struct sockaddr_in);
char* remote_dns = "10.3.9.45";
int is_listen;

void init_socket() {
    /* 初始化，否则无法运行socket */
    WORD wVersion = MAKEWORD(2, 2);
    WSADATA wsadata;
    if (WSAStartup(wVersion, &wsadata) != 0) {
        return;
    }

    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);

    /* 初始化两个结构体以留空 */
    memset(&client_addr, 0, sizeof(client_addr));
    memset(&server_addr, 0, sizeof(server_addr));

    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(PORT);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_dns);
    server_addr.sin_port = htons(PORT);

    // reuse port
    const int REUSE = 1;
    setsockopt(client_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&REUSE, sizeof(REUSE));

    if (bind(client_sock, (SOCKADDR*)&client_addr, addr_len) < 0)
    {
        printf("ERROR: Could not bind: %s\n", strerror(errno));
        exit(-1);
    }

    char* DNS_server = remote_dns;
    printf("\nDNS server: %s\n", DNS_server);
    printf("Listening on port 53\n\n");
}

/* 非阻塞模式 */
void nonblock() {
    int server_result = ioctlsocket(server_sock, FIONBIO, &mode);
    int client_result = ioctlsocket(client_sock, FIONBIO, &mode);

    if (server_result != 0 || client_result != 0) {
        // 设置失败
        printf("ioctlsocket failed with error: %d\n", WSAGetLastError());
        closesocket(server_sock);
        closesocket(client_sock);
        return ;
    }

    while (1) {
        receive_client(); // 接收来自客户端的数据
        receive_server(); // 接收来自服务器的数据
    }
}

void poll() {
    struct pollfd fds[2];

    while (1)
    {
        fds[0].fd = client_sock;
        fds[0].events = POLLIN;
        fds[1].fd = server_sock;
        fds[1].events = POLLIN;

        int ret = WSAPoll(fds, 2, 1);
        if (ret == SOCKET_ERROR)
        {
            printf("ERROR WSAPoll: %d.\n", WSAGetLastError());
        }
        else if (ret > 0)
        {
            if (fds[0].revents & POLLIN)
            {
                receive_client();
            }
            if (fds[1].revents & POLLIN)
            {
                receive_server();
            }
        }
    }
}

void close_server() {
    closesocket(client_sock);
    closesocket(server_sock);
    WSACleanup();
}

void receive_client() {
    uint8_t buffer[BUFFER_SIZE];        // 接收的报文
    uint8_t buffer_new[BUFFER_SIZE];    // 回复给客户端的报文
    dns_message msg;                    // 报文结构体
    uint8_t ip_addr[4] = { 0 };         // 查询域名得到的IP地址
    int msg_size = -1;                  // 报文大小
    int is_found = 0;                   // 是否查到

    msg_size = recvfrom(client_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);

    if (msg_size >= 0) {
        uint8_t* start = buffer;

        if (debug_mode == 1) {
            printf("\n------------------DNS message from client------------------\n");
        }

        /* 解析客户端发来的DNS报文，将其保存到msg结构体内 */
        get_message(&msg, buffer, start);

        /* 从缓存查找 */
        is_found = query_cache(msg.questions->q_name, ip_addr);

        /* 若cache未查到，则从host文件查找 */
        if (is_found == 0) {

           if (debug_mode == 1) {
               printf("Address not found in cache.\n");
           }

           is_found = query_node(list_trie, msg.questions->q_name, ip_addr);
           /* 若未查到，则上交远程DNS服务器处理*/
           if (is_found == 0) {
               /* 给将要发给远程DNS服务器的包分配新ID */
               uint16_t newID = set_ID(msg.header->id, client_addr);
               memcpy(buffer, &newID, sizeof(uint16_t));
               if (newID == ID_LIST_SIZE) {

                   if (debug_mode == 1) {
                       printf("ID list is full.\n");
                   }

               }
               else {
                   is_listen = 1;
                   sendto(server_sock, buffer, msg_size, 0, (struct sockaddr*)&server_addr, addr_len);
               }
               return ;
           }
       }

        uint8_t* end;
        end = set_message(&msg, buffer_new, ip_addr);

        int len = end - buffer_new;

        /* 将DNS应答报文发回客户端 */
        sendto(client_sock, buffer_new, len, 0, (struct sockaddr*)&client_addr, addr_len);
        
        if (log_mode == 1) {
            write_log(msg.questions->q_name, ip_addr);
        }
    }
}

void receive_server() {
    uint8_t buffer[BUFFER_SIZE];        // 接收的报文
    dns_message msg;
    int msg_size = -1;                  // 报文大小

    /* 接受远程DNS服务器发来的DNS应答报文 */
    if (is_listen == 1) {
        msg_size = recvfrom(server_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);

        if (debug_mode == 1) {
            printf("\n------------------DNS message from server------------------\n");
        }

        get_message(&msg, buffer, buffer);
    }

    /* 将DNS应答报文转发回客户端 */
    if (msg_size > 0 && is_listen == 1) {
        /* ID转换 */
        uint16_t ID = msg.header->id;
        uint16_t old_ID = htons(ID_list[ID].client_ID);
        memcpy(buffer, &old_ID, sizeof(uint16_t));        //把待发回客户端的包ID改回原ID

        struct sockaddr_in ca = ID_list[ID].client_addr;
        ID_list[ID].expire_time = 0;

        sendto(client_sock, buffer, msg_size, 0, (struct sockaddr*)&client_addr, addr_len);
        is_listen = 0;

        if (log_mode == 1) {
            write_log(msg.questions->q_name, NULL);
        }
    }
}