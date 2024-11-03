#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/mmu.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "lib/string.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);


struct lock filesys_lock; 


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
	lock_init (&filesys_lock);
}

static bool validate_ptr (const void *p, size_t size, bool writable) {

	if (p == NULL || !is_user_vaddr (p))
		return false;
	struct thread *cur = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ptr <= pg_round_down (p + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		if (pte == NULL ||
				is_kern_pte(pte) ||
				(writable && !is_writable (pte)))
			return false;
	}
	return true;
}



/* flide manager */
static bool
fd_sort (const struct list_elem *a, const struct list_elem *b) {
	const struct file_des *fda = list_entry (a, struct file_des, elem);
	const struct file_des *fdb = list_entry (a, struct file_des, elem);

	return fda->fd < fdb->fd;
}

static struct file_des * find_filde_by_fd (int32_t fd) {
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem *e;
	struct file_des *filde;

	for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)) {
		filde = list_entry (e, struct file_des, elem);
		if (filde->fd == fd)
			return filde;
	}
	return NULL;
}

static int
allocate_fd (void) {
	struct list *fd_list = &thread_current ()->fd_list;
	struct list_elem *e;
	struct file_des *filde;
	int32_t __fd = 0;
	for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e), __fd++) {
		filde = list_entry (e, struct file_des, elem);
		if (filde->fd != __fd)
			break;
	}
	return __fd;
}


bool clean_filde (struct file_des *filde) {
	if (filde) {
		free (filde);
		return true;
	}
	return false;
}

static uint64_t
fork (struct intr_frame *f) {
	char *name = (char *) f->R.rdi;


	lock_acquire(&filesys_lock);
	tid_t tid = process_fork (name, f);
	lock_release(&filesys_lock);

	return tid;
}

static int exec (struct intr_frame *f) {
	char *fn_copy;
	char *saved_ptr;
	
	const char *delimeter = " ";

	const char *fname = (const char *) f->R.rdi;

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		thread_exit ();

	strlcpy (fn_copy, fname, PGSIZE);
	if (strlen(fname) < PGSIZE) {
		fn_copy[strlen(fname) + 1] = 0;
	}
	fn_copy = strtok_r(fn_copy, delimeter, &saved_ptr);

	process_exec (fn_copy);

	NOT_REACHED(); // process_exec should not return anything!
	return -1;
}

static int create(struct intr_frame *f) {
	const char *file_name = (const char *) f->R.rdi;
	unsigned initial_size = (unsigned) f->R.rsi;

	char *copy_file_name = (char *) file_name;

	if (file_name == NULL || !is_user_vaddr (file_name) ){ // check if file is valid
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}

	// file 이름 끝이 null로 끝나는지 확인
	while (*copy_file_name != '\0') {
		if (!is_user_vaddr (copy_file_name)) {
			thread_current ()->exit_status = -1;
			thread_exit ();
			return -1;
		}
		copy_file_name++;
	}

	// TODO: create-bad-ptr test case

	lock_acquire (&filesys_lock);
	bool success = filesys_create (file_name, initial_size);
	lock_release (&filesys_lock);

	return success;
}

static int halt (void) {
	power_off ();
	return -1;
}

int remove(const char *file) {


	lock_acquire (&filesys_lock);
	bool success = filesys_remove (file);
	lock_release (&filesys_lock);

	return success;
}

int open (struct intr_frame *f) {
	const char *file_name = (const char *) f->R.rdi;
	struct thread *t = thread_current ();
	struct file *file;
	struct file_des *filde;
	int fd;
	int ret = -1;

	if (file_name == NULL || !is_user_vaddr (file_name)) {
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}


	lock_acquire(&filesys_lock); // lock the file system


	file = filesys_open(file_name);
	if  (file == NULL) {
		lock_release (&filesys_lock);
		return ret;
	}
	fd = allocate_fd ();
	if (fd < 0) { // Fd 할당 실패
		file_close (file);
		lock_release (&filesys_lock);
		return ret;
	}

	ret = 0;

	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
file_size (struct intr_frame *f) {
	struct file_des *filde;
	int32_t fd = f->R.rdi;

	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde)
		ret = file_length (filde->obj->file);
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
read (struct intr_frame *f) {
	struct file_des *filde;
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	int ret = -1;


	if (!validate_ptr (buf, size, true)){
		thread_current()->exit_status = -1;
		thread_exit();
	}

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);

	// msg("DEBUG: read. fd: %d", fd);

	if (filde) ret = file_read (filde->obj->file, buf, size);
	else ret = -1;


	// unlock the file system
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
write (struct intr_frame *f) {
	struct file_des *filde;
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	int ret = -1;

	if (!validate_ptr (buf, size, false)){
		thread_current ()->exit_status = -1;
		thread_exit ();
	}

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde) {
		switch (filde->type) {
			case STDIN:
				break;
			case STDOUT:
				putbuf (buf, size);
				ret = size;
				break;
			default:
				ret = file_write (filde->obj->file, buf, size);
				break;
		}
	}
	lock_release (&filesys_lock);
	return ret;
}

static uint64_t
seek (struct intr_frame *f) {
	struct file_des *filde;
	int32_t fd = f->R.rdi;
	unsigned position = f->R.rsi;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde && filde->obj)
		file_seek (filde->obj->file, position);
	lock_release (&filesys_lock);
	return 0;
}

static uint64_t
tell (struct intr_frame *f) {
	int32_t fd = f->R.rdi;
	struct file_des *filde;
	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);

	if (filde && filde->obj)
		ret = file_tell (filde->obj->file);
	lock_release (&filesys_lock);
	return ret;
}


int close (struct intr_frame *f) {
	struct thread *cur = thread_current();
    struct list_elem *e;
	int fd = f->R.rdi; // ?
	int ret = 1;

    for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
        struct file_des *fd_struct = list_entry(e, struct file_des, elem);
        
        if (fd_struct->fd == fd) {
            file_close(fd_struct->obj->file);      // 파일 닫기
            list_remove(e);                   // 리스트에서 제거
            free(fd_struct);                  // 메모리 해제
        }


    }
	// int32_t fd = f->R.rdi; // file descriptor
	// struct file_des *filde = find_filde_by_fd (fd);
	// int ret = -1;
	// if (filde == NULL) {
	// 	return ret;
	// }

	// lock_acquire (&filesys_lock);
	

	// list_remove (&filde->elem);
	// ret = clean_filde (filde);
	
	// lock_release (&filesys_lock);
	return ret;
}



/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// msg("DEBUG: syscall_handler. syscall number: %d", f->R.rax);
	switch (f->R.rax) {
		case SYS_HALT:
			halt ();
			NOT_REACHED ();
			break;
		case SYS_EXIT:
			thread_current ()->exit_status = f->R.rdi;
			thread_exit ();
			NOT_REACHED ();
			break;
		case SYS_FORK:
			f->R.rax = fork (f);
			break;
		case SYS_EXEC:
			f->R.rax = exec (f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f);
			break;
		case SYS_OPEN:
			f->R.rax = open (f);
			break;
		case SYS_FILESIZE:
			f->R.rax = file_size (f);
			break;
		case SYS_READ:
			f->R.rax = read (f);
			break;
		case SYS_WRITE:
			f->R.rax = write (f);
			break;
		case SYS_SEEK:
			f->R.rax = seek (f);
			break;
		case SYS_TELL:
			f->R.rax = tell (f);
			break;
		case SYS_CLOSE:
			f->R.rax = close (f);
			break;
		// case SYS_DUP2:
		// 	f->R.rax = SyS_dup2 (f);
		// 	break;
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
 }