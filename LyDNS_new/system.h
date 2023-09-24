#pragma once

#include "header.h"
#include "server.h"
#include "data_struct.h"

char* host_path;					// HOST文件目录
char* LOG_PATH;						// 日志文件目录

int debug_mode;
int log_mode;

void init(int argc, char* argv[]);
void get_config();
void print_help_info();
void read_host();
void get_host_info(FILE* ptr);
void write_log(char* domain, uint8_t* ip_addr);