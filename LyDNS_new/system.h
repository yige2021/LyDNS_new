#pragma once

#include "header.h"
#include "server.h"
#include "data_struct.h"

char* host_path;					// HOST�ļ�Ŀ¼
char* LOG_PATH;						// ��־�ļ�Ŀ¼

int debug_mode;
int log_mode;

void init(int argc, char* argv[]);
void get_config();
void print_help_info();
void read_host();
void get_host_info(FILE* ptr);
void write_log(char* domain, uint8_t* ip_addr);