#include "server.h"

int client_port;
int addr_len = sizeof(struct sockaddr_in);
char* remote_dns = "10.3.9.45";
int is_listen;

void init_socket() {
    /* ��ʼ���������޷�����socket */
    WORD wVersion = MAKEWORD(2, 2);
    WSADATA wsadata;
    if (WSAStartup(wVersion, &wsadata) != 0) {
        return;
    }

    client_sock = socket(AF_INET, SOCK_DGRAM, 0);
    server_sock = socket(AF_INET, SOCK_DGRAM, 0);

    /* ��ʼ�������ṹ�������� */
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

/* ������ģʽ */
void nonblock() {
    int server_result = ioctlsocket(server_sock, FIONBIO, &mode);
    int client_result = ioctlsocket(client_sock, FIONBIO, &mode);

    if (server_result != 0 || client_result != 0) {
        // ����ʧ��
        printf("ioctlsocket failed with error: %d\n", WSAGetLastError());
        closesocket(server_sock);
        closesocket(client_sock);
        return ;
    }

    while (1) {
        receive_client(); // �������Կͻ��˵�����
        receive_server(); // �������Է�����������
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
    uint8_t buffer[BUFFER_SIZE];        // ���յı���
    uint8_t buffer_new[BUFFER_SIZE];    // �ظ����ͻ��˵ı���
    dns_message msg;                    // ���Ľṹ��
    uint8_t ip_addr[4] = { 0 };         // ��ѯ�����õ���IP��ַ
    int msg_size = -1;                  // ���Ĵ�С
    int is_found = 0;                   // �Ƿ�鵽

    msg_size = recvfrom(client_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);

    if (msg_size >= 0) {
        uint8_t* start = buffer;

        if (debug_mode == 1) {
            printf("\n------------------DNS message from client------------------\n");
        }

        /* �����ͻ��˷�����DNS���ģ����䱣�浽msg�ṹ���� */
        get_message(&msg, buffer, start);

        /* �ӻ������ */
        is_found = query_cache(msg.questions->q_name, ip_addr);

        /* ��cacheδ�鵽�����host�ļ����� */
        if (is_found == 0) {

           if (debug_mode == 1) {
               printf("Address not found in cache.\n");
           }

           is_found = query_node(list_trie, msg.questions->q_name, ip_addr);
           /* ��δ�鵽�����Ͻ�Զ��DNS����������*/
           if (is_found == 0) {
               /* ����Ҫ����Զ��DNS�������İ�������ID */
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

        /* ��DNSӦ���ķ��ؿͻ��� */
        sendto(client_sock, buffer_new, len, 0, (struct sockaddr*)&client_addr, addr_len);
        
        if (log_mode == 1) {
            write_log(msg.questions->q_name, ip_addr);
        }
    }
}

void receive_server() {
    uint8_t buffer[BUFFER_SIZE];        // ���յı���
    dns_message msg;
    int msg_size = -1;                  // ���Ĵ�С

    /* ����Զ��DNS������������DNSӦ���� */
    if (is_listen == 1) {
        msg_size = recvfrom(server_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server_addr, &addr_len);

        if (debug_mode == 1) {
            printf("\n------------------DNS message from server------------------\n");
        }

        get_message(&msg, buffer, buffer);
    }

    /* ��DNSӦ����ת���ؿͻ��� */
    if (msg_size > 0 && is_listen == 1) {
        /* IDת�� */
        uint16_t ID = msg.header->id;
        uint16_t old_ID = htons(ID_list[ID].client_ID);
        memcpy(buffer, &old_ID, sizeof(uint16_t));        //�Ѵ����ؿͻ��˵İ�ID�Ļ�ԭID

        struct sockaddr_in ca = ID_list[ID].client_addr;
        ID_list[ID].expire_time = 0;

        sendto(client_sock, buffer, msg_size, 0, (struct sockaddr*)&client_addr, addr_len);
        is_listen = 0;

        if (log_mode == 1) {
            write_log(msg.questions->q_name, NULL);
        }
    }
}