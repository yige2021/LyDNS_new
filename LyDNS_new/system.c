#include "system.h"

char* host_path = "./dnsrelay.txt";
char* LOG_PATH;
int debug_mode = 0;
int log_mode = 0;

void init(int argc, char* argv[]) {
    mode = 0;           // Ĭ�Ϸ�����ģʽ
    is_listen = 0;      // ��ʼ������
    
    /* ��ȡ�������в��� */
    get_config(argc, argv);
    
    /* ��ʼ��socket */
    init_socket();

    /* ��ʼ��IDӳ��� */
    init_ID_list();

    /* ��ʼ������ */
    init_cache();

    /* ��ʼ��HOST�ļ� */
    read_host();
}

/* ��ȡ����������� */
void get_config(int argc, char* argv[]) {
    int index;
    argc--;

    print_help_info();

    for (index = 1; index <= argc; index++) {
        /* ����ģʽ */
        if (strcmp(argv[index], "-d") == 0) {
            debug_mode = 1;
        }

        /* ��־ģʽ */
        if (strcmp(argv[index], "-l") == 0) {
            log_mode = 1;
        }

        /* ���ϵͳ������Ϣ */
        else if (strcmp(argv[index], "-i") == 0) {
            printf("Hosts path: %s\n", host_path);
            printf("Remote DNS server address: %s (default: 10.3.9.45, BUPT DNS) \n", remote_dns);
            printf("mode: ");
            printf(mode == 0 ? "nonblock\n" : "poll\n");
        }

        /* ����Զ��DNS������ */
        else if (strcmp(argv[index], "-s") == 0) {
            char* addr = malloc(16);
            memset(addr, 0, 16);
            index++;
            memcpy(addr, argv[index], strlen(argv[index]) + 1);
            remote_dns = addr;
        }

        else if (strcmp(argv[index], "-m") == 0) {
            index++;
            if (strcmp(argv[index], "0") == 0) {
                mode = 0;
            }
            else if (strcmp(argv[index], "1") == 0) {
                mode = 1;
            }
        }
    }
}

void print_help_info() {

    printf("-------------------------------------------------------------------------------\n");
    printf("|                          Welcome to use LyDNS!                              |\n");
    printf("| Please submit your query by terminal, and watch the answer in your terminal.|\n");
    printf("|                  Example: nslookup www.baidu.com 127.0.0.1                  |\n");
    printf("|     Arguments: -i:                  print basic information                 |\n");
    printf("|                -d:                  print debug information                 |\n");
    printf("|                -l:                  print log                               |\n");
    printf("|                -s [server_address]: set remote DNS server                   |\n");
    printf("|                -m [mode]: set mode, 0: nonblock, 1: poll                    |\n");
    printf("-------------------------------------------------------------------------------\n");
}

void read_host() {
    FILE* host_ptr = fopen(host_path, "r");

    if (!host_ptr) {
        printf("Error! Can not open hosts file!\n");
        exit(1);
    }
    get_host_info(host_ptr);
}

void get_host_info(FILE* ptr) {
    int num = 0;
    while (!feof(ptr)) {
        uint8_t this_ip[4];

        fscanf(ptr, "%s", IPAddr);
        fscanf(ptr, "%s", domain);

        num++;

        transfer_IP(this_ip, IPAddr);
        add_node(list_trie, this_ip, domain);
    }

    if (debug_mode == 1) {
        printf("%d domain name address info has been loaded.\n\n", num);
    }
}

void write_log(char* domain, uint8_t* ip_addr)
{
    FILE* fp = fopen("./log.txt", "a");
    if (fp == NULL)
    {
        if (debug_mode == 1) {
            printf("File open failed.\n");
        }
    }
    else
    {        
        if (debug_mode == 1) {
            printf("File open succeed.\n");
        }
        // ��ȡ��ǰʱ��
        time_t currentTime = time(NULL);
        // ��ʱ��ת��Ϊ����ʱ��
        struct tm* localTime = localtime(&currentTime);
        // ��ʽ������ӡʱ��
        char timeString[100];
        strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", localTime);
        fprintf(fp, "%s  ", timeString);

        fprintf(fp, "%s  ", domain);
        if (ip_addr != NULL)
            fprintf(fp, "%d.%d.%d.%d\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
        else
            fprintf(fp, "Not found in local. Returned from remote DNS server.\n");

        // ˢ�»��������ر��ļ�
        fflush(fp);
        fclose(fp);
    }
}