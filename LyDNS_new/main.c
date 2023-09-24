#include "header.h"
#include "system.h"

int main(int argc, char* argv[]) {

    /* 初始化系统 */
    init(argc, argv);

    /* 以非阻塞模式运行 */
    if (mode == 0) {
        nonblock();
    }

    /* 以阻塞模式（poll）运行 */
    if (mode == 1) {
        poll();
    }

    /* 关闭连接 */
    close_server();
    return 0;
}