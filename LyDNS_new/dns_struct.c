#include "dns_struct.h"

size_t get_bits(uint8_t** buffer, int bits) {
    /* ntohs：网络字节顺序转换为主机字节顺序 */
    if (bits == 8) {
        uint8_t val;
        memcpy(&val, *buffer, 1);
        *buffer += 1;
        return val;
    }
    if (bits == 16) {
        uint16_t val;
        memcpy(&val, *buffer, 2);
        *buffer += 2;
        return ntohs(val);
    }
    if (bits == 32) {
        uint32_t val;
        memcpy(&val, *buffer, 4);
        *buffer += 4;
        return ntohl(val);
    }
}

void set_bits(uint8_t** buffer, int bits, int value) {
    /* ntohs：网络字节顺序转换为主机字节顺序 */
    if (bits == 8) {
        uint8_t val = ntohs(value);
        memcpy(*buffer, &val, 1);
        *buffer += 1;
    }
    if (bits == 16) {
        uint16_t val = ntohs(value);
        memcpy(*buffer, &val, 2);
        *buffer += 2;
    }
    if (bits == 32) {
        uint32_t val = ntohs(value);
        memcpy(*buffer, &val, 4);
        *buffer += 4;
    }
}

/* 把得到的DNS报文存到报头结构体 */
uint8_t* get_header(dns_message* msg, uint8_t* buffer) {
    msg->header->id = get_bits(&buffer, 16);

    uint16_t val = get_bits(&buffer, 16);

    msg->header->qr = (val & QR_MASK) >> 15;
    msg->header->opcode = (val & OPCODE_MASK) >> 11;
    msg->header->aa = (val & AA_MASK) >> 10;
    msg->header->tc = (val & TC_MASK) >> 9;
    msg->header->rd = (val & RD_MASK) >> 8;
    msg->header->ra = (val & RA_MASK) >> 7;
    msg->header->rcode = (val & RCODE_MASK) >> 0;

    msg->header->qdCount = get_bits(&buffer, 16);
    msg->header->anCount = get_bits(&buffer, 16);
    msg->header->nsCount = get_bits(&buffer, 16);
    msg->header->arCount = get_bits(&buffer, 16);

    if (debug_mode == 1) {
        print_header(msg);
    }

    return buffer;
}

/* 把报文头结构体存为网络字节序 */
uint8_t* set_header(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    dns_header* header = msg->header;
    header->qr = 1;        // 回答报文为1
    header->aa = 1;        // 权威域名服务器
    header->ra = 1;        // 可用递归
    header->anCount = 1;   // 1个回复
    if (ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0) {
        /* 若查到0.0.0.0，则该域名被屏蔽 */
        header->rcode = 3; // 名字错误
    }
    else {
        header->rcode = 0; // 无差错
    }

    set_bits(&buffer, 16, header->id);
    
    int flags = 0;
    flags |= (header->qr << 15) & QR_MASK;
    flags |= (header->opcode << 11) & OPCODE_MASK;
    flags |= (header->aa << 10) & AA_MASK;
    flags |= (header->tc << 9) & TC_MASK;
    flags |= (header->rd << 8) & RD_MASK;
    flags |= (header->ra << 7) & RA_MASK;
    flags |= (header->rcode << 0) & RCODE_MASK;

    set_bits(&buffer, 16, flags);
    set_bits(&buffer, 16, header->qdCount);
    set_bits(&buffer, 16, header->anCount);
    set_bits(&buffer, 16, header->nsCount);
    set_bits(&buffer, 16, header->arCount);

    return buffer;
}

uint8_t* get_question(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    int i;
    for (i = 0; i < msg->header->qdCount; i++) {
        char name[MAX_SIZE] = { 0 };
        dns_question* p = malloc(sizeof(dns_question));
       
        /* 从DNS报文中获取查询域名*/
        buffer = get_domain(buffer, name, start);

        p->q_name = malloc(strlen(name) + 1);
        memcpy(p->q_name, name, strlen(name) + 1);

        p->q_type = get_bits(&buffer, 16);
        p->q_class = get_bits(&buffer, 16);

        /* 头插法插入结点 */
        p->next = msg->questions;
        msg->questions = p;

        if (debug_mode == 1) {
            print_question(msg);
        }
    }

    return buffer;
}

uint8_t* set_question(dns_message* msg, uint8_t* buffer) {
    int i, j;
    for (i = 0; i < msg->header->qdCount; i++) {
        dns_question* p = msg->questions;
        buffer = set_domain(buffer, p->q_name);

        set_bits(&buffer, 16, p->q_type);
        set_bits(&buffer, 16, p->q_class);

        p = p->next;
    }
    return buffer;
}

uint8_t* get_answer(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    int i;
    for (i = 0; i < msg->header->anCount; i++) {
        char name[MAX_SIZE] = {0};
        dns_rr* p = malloc(sizeof(dns_rr));

        /* 从DNS报文中获取查询域名*/
        buffer = get_domain(buffer, name, start);       

        p->name = malloc(strlen(name) + 1);
        memcpy(p->name, name, strlen(name) + 1);

        p->type = get_bits(&buffer, 16);
        p->rr_class = get_bits(&buffer, 16);
        p->ttl = get_bits(&buffer, 32);
        p->rd_length = get_bits(&buffer, 16);

        /* 获取IPv4地址 */
        if (p->type == RR_A) {
            int j;
            for (j = 0; j < 4; j++) {
                p->rd_data.a_record.IP_addr[j] = get_bits(&buffer, 8);
            }
        }
        
        else {
            buffer += p->rd_length;
        }

        /* 头插法插入结点 */
        p->next = msg->answers;
        msg->answers = p;

        if (debug_mode == 1) {
            print_answer(msg);
        }
    }
    return buffer;
}

uint8_t* set_answer(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    int i;
    
    buffer = set_domain(buffer, msg->questions->q_name);

    set_bits(&buffer, 16, 1);    // type
    set_bits(&buffer, 16, 1);    // rr_class
    set_bits(&buffer, 32, 4);    // ttl
    set_bits(&buffer, 16, 4);    // rd_length

    for (i = 0; i < 4; i++) {
        *buffer = ip_addr[i];
        buffer++;
    }

    return buffer;
}

uint8_t* get_domain(uint8_t* buffer, char* name, uint8_t* start) {
    uint8_t* ptr = buffer;
    int i = 0, j = 0;
    int len = 0;

    /* 若第一个字节的前2位为11，则表示指针，后14位为偏移量，跳转到DNS报文段起始地址 + 偏移量处 */
    if (*ptr >= 0xc0) {
        uint16_t offset = *ptr;
        offset &= 0x3f;
        offset <<= 8;
        offset += *(ptr + 1);   // 获取后14位偏移量
        get_domain(start + offset, name, start);
        return buffer + 2;
    }

    while (1) {
        uint8_t val = *ptr;
        ptr++;

        /* 读到00或指针，则结束读入域名 */
        if (val == 0 || val >= 0xc0) {
            return ptr;
        }

        /* 若此时待读字符数为0，则开始读入字符 */
        else if (len == 0) {
            len = val;
            if (i != 0) {
                name[i++] = '.';
            }
        }
        else if (len != 0) {
            name[i++] = val;
            len--;
        }
    }

    if (*ptr >= 0xc0) {
        char name2[MAX_SIZE] = { 0 };
        uint16_t offset = (*ptr & 0x3f) << 8 + *(ptr + 1);   // 获取后14位偏移量
        uint16_t* end = get_domain(start + offset, name, start);
        for (j = 0; j < strlen(name2); j++) {
            name[i + j] = name2[j];
        }
        ptr += 2;
    }

    else if (*ptr == 0) {
        ptr++;
    }

    return ptr;
}

uint8_t* set_domain(uint8_t* buffer, char* name) {
    uint8_t* ptr = name;
    char tmp[MAX_SIZE] = { 0 };
    int i = 0;

    uint8_t* s = buffer;

    while (1) {
        if (*ptr == 0) {
            *buffer = i;
            buffer++;
            memcpy(buffer, tmp, i);
            buffer += i;

            *buffer = 0;
            buffer++;
            break;
        }
        else if (*ptr != '.') {
            tmp[i++] = *ptr;
        }
        else if (*ptr == '.') {
            *buffer = i;
            buffer++;
            memcpy(buffer, tmp, i);
            buffer += i;
            memset(tmp, 0, sizeof(tmp));
            i = 0;
        }
        ptr++;
    }

    return buffer;
}

/* 解析收到的报文 */
void get_message(dns_message* msg, uint8_t* buffer, uint8_t* start) {
    /* 开辟空间 */
    msg->header = malloc(sizeof(dns_header));
    msg->questions = malloc(sizeof(dns_question));
    msg->answers = malloc(sizeof(dns_rr));

    /* 获取报文头 */
    buffer = get_header(msg, buffer);   // buffer指向读取完报头后的地址  

    /* 获取询问内容 */
    buffer = get_question(msg, buffer, start); // buffer指向读取完询问内容后的地址

    /* 获取应答内容 */
    buffer = get_answer(msg, buffer, start);   // buffer指向读取完应答内容后的地址
}

/* 组装将要发出的报文，只发给客户端 */
uint8_t* set_message(dns_message* msg, uint8_t* buffer, uint8_t* ip_addr) {
    uint8_t* start = buffer;

    /* 组装报头 */
    buffer = set_header(msg, buffer, ip_addr);
    /* 组装询问 */
    buffer = set_question(msg, buffer);
    /* 组装回答 */
    buffer = set_answer(msg, buffer, ip_addr);

    return buffer;
}

void free_message(dns_message* msg) {
    free(msg->header);

    dns_question* p = msg->questions;
    while (p) {
        dns_question* tmp = p;
        p = p->next;
        free(tmp);
    }

    p = msg->answers;
    while (p) {
        dns_question* tmp = p;
        p = p->next;
        free(tmp);
    }
    
    free(msg);
}