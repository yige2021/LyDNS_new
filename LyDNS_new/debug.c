#include "debug.h"

void print_header(dns_message* msg) {
	printf("-----------header-----------\n");
	printf("ID = %d, ", msg->header->id);
	printf("qr = %d, ", msg->header->qr);
	printf("opcode = %d, ", msg->header->opcode);
	printf("aa = %d, ", msg->header->aa);
	printf("tc = %d, ", msg->header->tc);
	printf("rd = %d, ", msg->header->rd);
	printf("ra = %d, ", msg->header->ra);
	printf("rcode = %d, ", msg->header->rcode);
	printf("qdCount = %d, ", msg->header->qdCount);
	printf("anCount = %d, ", msg->header->anCount);
	printf("nsCount = %d, ", msg->header->nsCount);
	printf("arCount = %d\n", msg->header->arCount);
}

void print_question(dns_message* msg) {
	printf("-----------question-----------\n");
	printf("domain: %s, ", msg->questions->q_name);
	printf("query type: %d, ", msg->questions->q_type);
	printf("query class: %d\n", msg->questions->q_class);
}

void print_answer(dns_message* msg) {
	printf("-----------answer-----------\n");
	printf("domain: %s, ", msg->answers->name);
	printf("answer type: %d, ", msg->answers->type);
	printf("resource record class: %d, ", msg->answers->rr_class);
	printf("time to live: %d, ", msg->answers->ttl);
	printf("record length: %d, ", msg->answers->rd_length);

    /* IPv4µØÖ· */
    if (msg->answers->type == RR_A) {
        printf("A Record: ");
        int j;
        for (j = 0; j < 3; j++) {
            printf("%d.", msg->answers->rd_data.a_record.IP_addr[j]);
        }
		printf("%d", msg->answers->rd_data.a_record.IP_addr[3]);
    }
	printf ("\n");
}