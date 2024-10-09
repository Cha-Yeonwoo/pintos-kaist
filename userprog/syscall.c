#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	uint64_t syscall_num = f->R.rax;
	if (syscall_num == SYS_EXIT) {
		thread_exit();
	} 
	else if (syscall_num == SYS_HALT){
		halt();
	}
	else if (syscall_num == SYS_FORK){
		// f->R.rax = fork(f); => fork 구현 필요
		f->R.rax = 0;

	}
	else if (syscall_num == SYS_WAIT){
		// f->R.rax = wait(f->R.rdi);
	}
	else if (syscall_num == SYS_EXIT){
		exit(f->R.rdi);
	}
	else {
		printf("Unhandled system call: %d\n", syscall_num);
		thread_exit();
	}

	printf ("system call!\n");
	// thread_exit (); 일단 이거 빼고 해보자
}


int fork(struct intr_frame *f){
	f->R.rax = 0;
	return 0;
}

int wait(int pid){
	
}

int halt(void){
	power_off();
	return 0;
}	

int exec(const char *cmd_line){
	if (cmd_line == NULL){
		return -1;
	}
	char *cmd_copy = malloc(strlen(cmd_line) + 1);

	strlcpy(cmd_copy, cmd_line, strlen(cmd_line) + 1);
	int pid = process_exec(cmd_copy);
	

	return pid;

	
}

int exit(int status){
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	return 0;
}
int read(int fd, void *buffer, unsigned size){
	return 0;
}

int write(int fd, const void *buffer, unsigned size){
	// TODO: Implement write system call
	return 0;
}

int open(const char *file){
	if (file == NULL){
		return -1;
	}
	return 0;
}