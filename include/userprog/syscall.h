#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdint.h>
#include "threads/thread.h"

void syscall_init (void);
bool clean_filde (struct filde *filde);

#endif /* userprog/syscall.h */
