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

static bool is_bad_name (void *p) {
	if (p == NULL || !is_user_vaddr (p))
		return true;

	struct thread *cur = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ; ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		if (pte == NULL || is_kern_pte(pte))
			return true;

		for (; *(char *)p != 0; p++);
		if (*(char *)p == 0)
			return false;
	}
}

 // allocate file descriptor to the file
 // fd_list is sorted by fd
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


int fork (struct intr_frame *f) {
	char *file_name = (char *) f->R.rdi;

	if (file_name == NULL || !is_user_vaddr (file_name)) {
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}

	if (is_bad_name (file_name)) {
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}

	lock_acquire(&filesys_lock);
	tid_t tid = process_fork (file_name, f);
	lock_release(&filesys_lock);

	return tid;
}

int exec (struct intr_frame *f) {
	char *fn_copy;
	char *saved_ptr;
	
	const char *delimeter = " ";

	const char *file_name = (const char *) f->R.rdi;

	if (file_name == NULL || !is_user_vaddr (file_name) || is_bad_name (file_name)) {
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}

	fn_copy = palloc_get_page (0);

	if (fn_copy == NULL){
		thread_exit ();
		return -1;
	}

	strlcpy (fn_copy, file_name, PGSIZE);
	if (strlen(file_name) < PGSIZE) {
		// null terminate the string
		fn_copy[strlen(file_name) + 1] = 0;
	}

	fn_copy = strtok_r(fn_copy, delimeter, &saved_ptr); // get the first token

	process_exec (fn_copy);

	NOT_REACHED(); // process_exec should not return anything!

	return -1;
}

static int create(struct intr_frame *f) {

	char *file_name = (char *) f->R.rdi;
	unsigned initial_size = f->R.rsi;
	int ret = -1;

	char *empty_name = "";

	if (is_bad_name(file_name) || !strcmp (file_name, empty_name)){
		thread_current ()->exit_status = -1;
		thread_exit ();
		return -1;
	}

	lock_acquire (&filesys_lock);
	ret = filesys_create (file_name, initial_size);
	lock_release (&filesys_lock);

	return ret;
}

static int halt (void) {
	power_off (); // shutdown the system
	return -1;
}

int remove(const char *file) {
	int ret = -1;
	if (file == NULL || !is_user_vaddr (file)|| is_bad_name (file)) {
		thread_current ()->exit_status = -1;
		thread_exit ();
		return ret;
	}

	lock_acquire (&filesys_lock);
	ret = filesys_remove (file);
	lock_release (&filesys_lock);

	return ret;
}

int open (struct intr_frame *f) {
	char *file_name = (char *) f->R.rdi;
	struct thread *t = thread_current ();
	struct file *file;
	struct file_des *filde;
	int fd;
	int ret = -1;

	if (is_bad_name(file_name)){
		thread_current ()->exit_status = -1;
		thread_exit ();
		return ret;
	}

	lock_acquire(&filesys_lock);
	fd = allocate_fd ();
	// msg("DEBUG : fd = %d", fd);
	if (fd >= 0) {
		file = filesys_open(file_name);
		if (file) {
			filde = (struct file_des *) malloc (sizeof (struct file_des));
			if (filde) {
				struct file *obj = (struct file *) malloc (sizeof (struct file));
				if (obj) {
					ret = fd;
					*obj = (struct file) {
						.ref_count = 1,
						.inode = file->inode,
						.pos = file->pos,
						.deny_write = file->deny_write

					};
					*filde = (struct file_des) {
						.fd = ret,
						.file = file,
						.type = FILE,
					};
					list_insert_ordered (&t->fd_list, &filde->elem, fd_sort, NULL);
				} else
					free (filde);
			} else
				file_close (file);
		}
	}
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
	if (filde) ret = file_length (filde->file);
	lock_release (&filesys_lock);
	return ret;
}

int read (struct intr_frame *f) {
	
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	size_t read_bytes = 0;
	struct file_des *filde;
	int ret = -1;
	struct thread *cur= thread_current ();

	void *ptr;

	// check the buffer is valid
	if (buf == NULL || !is_user_vaddr (buf)){
		cur->exit_status = -1;
		thread_exit ();
		return -1;
	}

	ptr = pg_round_down (buf);
	for (; ptr <= pg_round_down (buf + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		if (pte == NULL ||is_kern_pte(pte) ){
			cur->exit_status = -1;
			thread_exit ();
			return -1;
		}
	}

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde) {
		switch (filde->type) {
			case STDIN:
				for (; read_bytes < size; read_bytes++)
					buf[read_bytes] = input_getc ();
				break;
			case STDOUT:
				ret = -1;
				break;
			default:
				ret = file_read (filde->file, buf, size);
				break;
		}
	}
	lock_release (&filesys_lock);
	return ret;

}

int write (struct intr_frame *f) {
	int fd = f->R.rdi;
	char *buf = (char *) f->R.rsi;
	size_t size = f->R.rdx;
	struct file_des *filde;
	int ret = -1;
	struct thread *cur = thread_current ();

	void *ptr;
	// check the buffer is valid
	if (buf == NULL || !is_user_vaddr (buf)){
		cur->exit_status = -1;
		thread_exit ();
		return -1;
	}

	ptr = pg_round_down (buf); 

	for (; ptr <= pg_round_down (buf + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		// check the page is valid
		if (pte == NULL ||is_kern_pte(pte)|| !is_writable (pte)){
			cur->exit_status = -1;
			thread_exit ();
			return -1; // 걸쳐있으면 바로 종료
		}
	}

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde) {
		if (filde->type == STDIN) {
			// cannot write to stdin
			lock_release (&filesys_lock);
			return -1;
		}
		else if (filde->type == STDOUT) {
				putbuf (buf, size);  // write to console
				ret = size;
		}
		else{
			ret = file_write (filde->file, buf, size); // write to file
		}
	}
	// filde is NULL -> error
	lock_release (&filesys_lock);
	return ret;
}


int seek (struct intr_frame *f) {
	struct file_des *filde;
	int32_t fd = f->R.rdi;
	unsigned position = f->R.rsi; // position to seek

	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde && filde->type == FILE)
		file_seek (filde->file, position);
	lock_release (&filesys_lock);
	ret = 0;
	return ret;
}

int tell (struct intr_frame *f) {
	int fd = f->R.rdi;
	struct file_des *filde;
	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);

	if (filde && filde->type == FILE)
		ret = file_tell (filde->file);
	lock_release (&filesys_lock);
	return ret;
}



bool
clean_filde (struct file_des *filde) {
	if (filde) {
		if (filde->type == FILE){
			if (filde->file->ref_count == 1) {
				filde->file->ref_count = 0;
				file_close (filde->file);
			}
		}
		free (filde);
		return true;
	}
	return false;
}
int close (struct intr_frame *f) {
	struct thread *cur = thread_current();
    struct list_elem *e;
	int fd = f->R.rdi;

	int ret = -1;

    // for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
    //     struct file_des *fd_struct = list_entry(e, struct file_des, elem);
        
    //     if (fd_struct->fd == fd) {
    //         file_close(fd_struct->file);      // 파일 시스템에서 파일 닫기
    //         list_remove(e);                   // fd_list에서 제거
    //         free(fd_struct);                  // 파일 디스크립터 구조체 메모리 해제
    //         return ret;
    //     }
    // }
	// ret = 0;
	// return ret;


	lock_acquire (&filesys_lock);
	struct file_des *filde = find_filde_by_fd (fd);
	if (filde) {
		list_remove (&filde->elem);

		if (filde->type == FILE){
			if (filde->file->ref_count == 1) {
				filde->file->ref_count = 0;
				file_close (filde->file);
			}
		}
		free (filde);

	}

	lock_release (&filesys_lock);
	return ret;	

}



/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// msg("DEBUG: syscall_handler. syscall number: %d", f->R.rax);
	// f-R.rax: system call number (syscall-nr.h)
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