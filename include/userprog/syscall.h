#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include "threads/thread.h"

#include "threads/interrupt.h"
#include "threads/thread.h"

void syscall_init (void);
bool clean_filde (struct filde *filde);

/* For file */


struct file_des { // file descriptor
	int fd;
	struct list_elem elem; // 리스트에서의 위치
	struct file *file;
	int is_file;
};

struct dfile {
	struct file *file;
	struct list_elem elem;
};


struct lock filesys_lock;  // file system lock

#endif /* userprog/syscall.h */
