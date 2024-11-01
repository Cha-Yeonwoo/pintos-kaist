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

/* Big lock for filesystem. */
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

static void
error_die (void) {
	thread_current ()->exit_status = -1;
	thread_exit ();
}

static bool
validate_ptr (const void *p, size_t size, bool writable) {
	if (p == NULL || !is_user_vaddr (p))
		return false;
	struct thread *current = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ptr <= pg_round_down (p + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (current->pml4, (uint64_t) ptr, 0);
		if (pte == NULL ||
				is_kern_pte(pte) ||
				(writable && !is_writable (pte)))
			return false;
	}
	return true;
}

static bool
validate_string (const void *p) {
	if (p == NULL || !is_user_vaddr (p))
		return false;
	struct thread *current = thread_current ();
	void *ptr = pg_round_down (p);
	for (; ; ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (current->pml4, (uint64_t) ptr, 0);
		if (pte == NULL || is_kern_pte(pte))
			return false;

		for (; *(char *)p != 0; p++);
		if (*(char *)p == 0)
			return true;
	}
}

/* flide manager */
static bool
fd_sort (const struct list_elem *A, const struct list_elem *B, void *_a UNUSED) {
	const struct filde *fdA = list_entry (A, struct filde, elem);
	const struct filde *fdB = list_entry (B, struct filde, elem);

	return fdA->fd < fdB->fd;
}

static struct filde *
get_filde_by_fd (int32_t fd) {
	struct list *fd_list = &thread_current()->fd_list;
	struct list_elem *e;
	struct filde *filde;
	for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)) {
		filde = list_entry (e, struct filde, elem);
		if (filde->fd == fd)
			return filde;
	}
	return NULL;
}

static int
allocate_fd (void) {
	struct list *fd_list = &thread_current ()->fd_list;
	struct list_elem *e;
	struct filde *filde;
	int32_t __fd = 0;
	for (e = list_begin (fd_list);
			e != list_end (fd_list);
			e = list_next (e), __fd++) {
		filde = list_entry (e, struct filde, elem);
		if (filde->fd != __fd)
			break;
	}
	return __fd;
}

static void
deref_file_obj (struct file_obj *obj) {
	ASSERT (obj != NULL);
	ASSERT (obj->ref_cnt > 0);

	if (--obj->ref_cnt == 0) {
		file_close (obj->file);
		free (obj);
	}
}

bool
clean_filde (struct filde *filde) {
	if (filde) {
		if (filde->type == FILE)
			deref_file_obj (filde->obj);
		free (filde);
		return true;
	}
	return false;
}

static uint64_t
SyS_fork (struct intr_frame *f) {
	const char *name = (const char *) f->R.rdi;

	if (!validate_string (name))
		error_die ();

	lock_acquire(&filesys_lock);
	tid_t tid = process_fork (name, f);
	lock_release(&filesys_lock);

	return tid;
}

static uint64_t
SyS_exec (struct intr_frame *f) {
	char *fn_copy;
	char *unused;
	const char *fname = (const char *) f->R.rdi;

	if (!validate_string (fname))
		error_die ();

	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		thread_exit ();

	strlcpy (fn_copy, fname, PGSIZE);
	if (strlen(fname) < PGSIZE) {
		fn_copy[strlen(fname) + 1] = 0;
	}
	fn_copy = strtok_r(fn_copy, " ", &unused);

	process_exec (fn_copy);
	NOT_REACHED();
	return -1;
}



/* The main system call interface */
// void
// syscall_handler (struct intr_frame *f UNUSED) {
// 	// TODO: Your implementation goes here.
// 	printf ("system call!\n");
// 	thread_exit ();
// }
void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_HALT:
			power_off ();
			NOT_REACHED ();
			break;
		case SYS_EXIT:
			thread_current ()->exit_status = f->R.rdi;
			thread_exit ();
			NOT_REACHED ();
			break;
		case SYS_FORK:
			f->R.rax = SyS_fork (f);
			break;
		case SYS_EXEC:
			f->R.rax = SyS_exec (f);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		// case SYS_CREATE:
		// 	f->R.rax = SyS_create (f);
		// 	break;
		// case SYS_REMOVE:
		// 	f->R.rax = SyS_remove (f);
		// 	break;
		// case SYS_OPEN:
		// 	f->R.rax = SyS_open (f);
		// 	break;
		// case SYS_FILESIZE:
		// 	f->R.rax = SyS_filesize (f);
		// 	break;
		// case SYS_READ:
		// 	f->R.rax = SyS_read (f);
		// 	break;
		// case SYS_WRITE:
		// 	f->R.rax = SyS_write (f);
		// 	break;
		// case SYS_SEEK:
		// 	f->R.rax = SyS_seek (f);
		// 	break;
		// case SYS_TELL:
		// 	f->R.rax = SyS_tell (f);
		// 	break;
		// case SYS_CLOSE:
		// 	f->R.rax = SyS_close (f);
		// 	break;
		// case SYS_DUP2:
		// 	f->R.rax = SyS_dup2 (f);
		// 	break;
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
 }
