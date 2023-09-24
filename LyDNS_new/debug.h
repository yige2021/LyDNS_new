#pragma once

#include "dns_struct.h"

void print_header(dns_message* msg);

void print_question(dns_message* msg);

void print_answer(dns_message* msg);