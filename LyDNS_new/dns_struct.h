#pragma once

#include "header.h"
#include "default.h"
#include "system.h"

/*
    ��ͷ�ļ�ר�����ڴ��DNS���Ľṹ��Message�Ķ��壬�Լ�һ���й�DNS���ĵĲ���
    DNS ���ĸ�ʽ���£�
    +---------------------+
    |        Header       | ����ͷ���̶�12�ֽڣ��ɽṹ��DNS_header�洢
    +---------------------+
    |       Question      | �������������Ĳ�ѯ�����ɽṹ��DNS_question�洢
    +---------------------+ 
    |        Answer       | ���ڲ�ѯ����Ļظ�
    +---------------------+
    |      Authority      | ָ����Ȩ����������
    +---------------------+
    |      Additional     | ������Ϣ
    +---------------------+
    �������������ɽṹ��DNS_resource_record�洢
*/

typedef struct DNS_message {
    struct DNS_header* header;
    struct DNS_question* questions;
    struct DNS_resource_record* answers;
    struct DNS_resource_record* authorities;
    struct DNS_resource_record* additionals;
} dns_message;

typedef struct DNS_header {
    uint16_t id; // ��ʶ����һ��DNS��ѯ�ͻָ���ID��ͬ 

    /* ���±���ռ�ÿռ��С��Ϊ�������أ��ʶ���λ��ѹ���ռ��Ը�Ч�����ڴ� */
    uint8_t qr:1;     // 0 ��ѯ 1 �ظ�
    uint8_t opcode:4; // 0 ��׼��ѯ 1 �����ѯ 2 ������״̬����
    uint8_t aa:1;     // ��Ȩ�ش����Ϊ1����ʾ�ظ���Question���ֲ�ѯ��������������Ȩ�������� 
    uint8_t tc:1;     // �ضϣ����Ϊ1����ʾ������Ϣ�����ŵ������ƶ����ض� 
    uint8_t rd:1;     // �����ݹ飺���Ϊ1����ʾ���������������ݹ��ѯ�������
    uint8_t ra:1;     // ���õݹ飺���Ϊ1����ʾ�ݹ��ѯ����������������Ч
    uint8_t z:3;      // Ԥ���ֶ�
    uint8_t rcode:4;  // ������ 0 �޲�� 1 ��ʽ���� 2 ���������� 3 ���ִ��� 4 ��ʵ�� 5 �ܾ� 6 - 15 ����

    /* ���±�����С��Ϊ16λ */
    uint16_t qdCount; // ��������ͨ����1��
    uint16_t anCount; // �ش���
    uint16_t nsCount; // ��Ȩ��
    uint16_t arCount; // ������
} dns_header;

typedef struct DNS_question {
    char* q_name;              // ������IP��ַ
    uint16_t q_type;           // ��Դ����
    uint16_t q_class;          // ��ַ���ͣ�ͨ��Ϊ1
    struct DNS_question* next;
} dns_question;

union ResourceData {
    /* IPv4 */
    struct {
        uint8_t IP_addr[4];
    } a_record;

    /* SOA��Ȩ����¼����ʼ */
    struct {
        char* MName;        // ������������
        char* RName;        // ����Ա����
        uint32_t serial;    // �汾��
        uint32_t refresh;   // ˢ�����ݼ��
        uint32_t retry;     // ���Լ��
        uint32_t expire;    // ��ʱ�ش�ʱ��
        uint32_t minimum;   // Ĭ������ʱ��
    } soa_record;

    /* cname�淶���Ƽ�¼ */
    struct {
        char* name;
    } cname_record;
};

typedef struct DNS_resource_record {
    char* name;                  // ����
    uint16_t type;               // resource data����
    uint16_t rr_class;           // ��֧��1��IN��������
    uint32_t ttl;                // ������RR�������ʱ��
    uint16_t rd_length;          // RDATA���ֵĳ���
    union ResourceData rd_data;  // ��Դ����
    struct DNS_resource_record* next;
} dns_rr;

typedef struct record {
    uint8_t addr[16];
    char* txt_data;
} dns_record;

/* ���ڻ�ȡDNS����ͷ��ֵ������ */
static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t RCODE_MASK = 0x000F;

size_t get_bits(uint8_t** buffer, int bits);

void set_bits(uint8_t** buffer, int bits, int value);

uint8_t* get_domain(uint8_t* buffer, char* name, uint8_t* start);

uint8_t* set_domain(uint8_t* buffer, char* name);

void get_message(dns_message* msg, uint8_t* buffer, uint8_t* start);

uint8_t* set_message(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

uint8_t* get_header(dns_message* msg, uint8_t* buffer);

uint8_t* set_header(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

uint8_t* get_question(dns_message* msg, uint8_t* buffer, uint8_t* start);

uint8_t* set_question(dns_message* msg, uint8_t* buffer);

uint8_t* get_answer(dns_message* msg, uint8_t* buffer, uint8_t* start);

uint8_t* get_answer(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr);

void free_message(dns_message* msg);