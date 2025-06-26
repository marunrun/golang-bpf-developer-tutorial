#pragma once


#define TASK_COMM_LEN 16
#define MAX_SLOTS 26

struct hist
{
 __u32 slots[MAX_SLOTS];
 unsigned char comm[TASK_COMM_LEN];
};



