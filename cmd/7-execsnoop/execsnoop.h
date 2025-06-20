
#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16

struct event {
    int pid;
    int ppid;
    int uid;
    int retval;
    _Bool is_exit;
    unsigned char comm[TASK_COMM_LEN];
};
#endif