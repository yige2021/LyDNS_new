#include "header.h"
#include "system.h"

int main(int argc, char* argv[]) {

    /* ��ʼ��ϵͳ */
    init(argc, argv);

    /* �Է�����ģʽ���� */
    if (mode == 0) {
        nonblock();
    }

    /* ������ģʽ��poll������ */
    if (mode == 1) {
        poll();
    }

    /* �ر����� */
    close_server();
    return 0;
}