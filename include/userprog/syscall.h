#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "threads/thread.h"

void syscall_init (void);

/* For file */
struct file_obj {
	struct file *file;
	int ref_cnt;
};

struct file_des { // file descriptor
	enum { STDIN, STDOUT, FILE } type;
	int fd;
	struct list_elem elem; // 리스트에서의 위치
	struct file_obj *obj;
};


#endif /* userprog/syscall.h */
