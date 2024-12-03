#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#include "threads/malloc.h"
#ifdef VM
#include "vm/vm.h"
#endif

#define BUFFER 150

static void process_cleanup (void);
static bool load (char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (struct thread *parent, struct semaphore *sema) {
 	struct thread *cur = thread_current ();

	cur->wait_on_exit = true; // true when the thread is waiting for the child to exit

	sema_init (&cur->wait_sema, 0);
	sema_init (&cur->exit_sema, 0);
	
	cur->exit_status = -1;
	lock_acquire (&parent->lock_for_child);
	// child list에 현재 thread를 추가한다.
	list_push_back (&parent->child_list, &cur->child_elem);
	lock_release (&parent->lock_for_child);

	sema_up (sema);
}

struct initd_aux { // initd에 parent와 filename을 모두 넘겨 주기 위해 구조체 사용
	struct thread *parent;
	char *file_name;
};

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	const char *delimeter = " ";

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	// PGSIZE (4096)보다 작으면, fn_copy의 마지막에 null을 넣어준다.
	strlcpy (fn_copy, file_name, PGSIZE); // copy the file name to fn_copy

	if (strlen(file_name) < PGSIZE) {
		fn_copy[strlen(file_name) + 1] = 0;
	}
	// strtok_r을 사용하여 fn_copy를 delimeter로 나눈다.
	fn_copy = strtok_r(fn_copy, delimeter, &fn_copy);

	/* Create a new thread to execute FILE_NAME. */
	// tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	struct initd_aux *aux =
		(struct initd_aux *) malloc (sizeof (struct initd_aux)); // file_name과 thread를 저장할 aux를 생성

	aux->file_name = fn_copy; // copy the file name to the aux

	aux->parent = thread_current ();
	sema_init (&aux->parent->sema_for_init, 0); 

	tid = thread_create (fn_copy, PRI_DEFAULT, initd, aux); // create a new thread to execute FILE_NAME

	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	else
		sema_down(&aux->parent->sema_for_init); 
	
	free (aux);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *aux) {
	struct initd_aux *aux_copy = (struct initd_aux *) aux;
	// struct thread *parent = (struct thread *) aux_;
	char *f_name = aux_copy ->file_name;
	struct thread *current = thread_current ();

	struct file_des *filde = (struct file_des *) malloc (sizeof (struct file_des));

	// STDIN file descriptor를 생성한다. (0)
	filde->fd = 0; // in일 경우 0
	filde->is_file = 0;
	list_push_back (&current->fd_list, &filde->elem);

	filde = (struct file_des *) malloc (sizeof (struct file_des));

	// STDOUT file descriptor를 생성한다. (1)
	filde->fd = 1; // out일 경우 1
	filde->is_file = 1;

	list_push_back (&current->fd_list, &filde->elem); // push back the file descriptor to the fd_list

#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init (aux_copy->parent, &aux_copy->parent->sema_for_init);

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

struct fork_aux {
	struct thread *parent;
	struct intr_frame if_;
	// struct semaphore dial;
	bool succ;
};


/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_ ) {
	/* Clone current thread to new thread.*/
	struct fork_aux *aux = malloc (sizeof (struct fork_aux));
	if (!aux)
		return TID_ERROR;
	aux->parent = thread_current ();
	memcpy (&aux->if_, if_, sizeof (struct intr_frame));

	// sema_init (&aux->dial, 0);
	sema_init (&aux->parent->sema_for_fork, 0);
	tid_t tid = thread_create (name, thread_current()->priority, __do_fork, aux);

	if (tid != TID_ERROR)
		sema_down(&aux->parent->sema_for_fork);
		// sema_down (&aux->dial);
	if (!aux->succ) tid = TID_ERROR;
	free (aux);

	// msg("DEBUG: process_fork tid = %d", tid); 
	// wait이 이상하다?
	return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	// pte: page table entry
	// va: virtual address
	// aux: additional data
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr (va)) return true;
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page (PAL_USER);

	if (newpage == NULL) return false;
	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable (pte); // check the page is writable or not

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		palloc_free_page (newpage); // free the allocated page
		return false;
	}
	return true;
}
#endif

struct fd_map {
	struct entry {
		struct file *parent;
		struct file *child;
	} entries[0];  // 크기가 정해지지 않은 배열
	int size;
};

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux_) { // parent 정보 받아야함. interupt frame
	struct intr_frame if_;
	struct fork_aux *aux = (struct fork_aux *) aux_; // fork_aux!

	struct thread *parent = aux->parent; // 
	struct thread *current = thread_current ();

	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if = &aux->if_;
	bool succ = false;

	bool free_flag = false; // map을 free할지 말지 결정하는 flag

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->exit_status = 0;
	current->pml4 = pml4_create();
	if (current->pml4 == NULL) goto out;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt)){
		// msg("DEBUG: supplemental_page_table_copy failed");
		goto error;
	}
		// goto out; // 일단.. 
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto out;
#endif

	/* ret = 0 */
	if_.R.rax = 0;
	/* Your code goes here.
	 * Hint) To duplicate the file object, use `file_duplicate`
	 *       in include/filesys/file.h. Note that parent should not return
	 *       from the fork() until this function successfully duplicates
	 *       the resources of parent.*/

	/* Duplicate FDs: the parent holds the filesystem lock */
	struct file *new_file; // new file object
	struct list_elem *e;
	struct file_des *filde;
	struct list *fd_list = &parent->fd_list;


	
	struct file** oldfiles = (struct file **) calloc(list_size(fd_list), sizeof(struct file *));
	if (!oldfiles) { goto out; }
	struct file** newfiles = (struct file **) calloc(list_size(fd_list), sizeof(struct file *));
	if (!newfiles) { free(oldfiles); goto out; }
	int lastIndex = 0;

	for (e = list_begin (fd_list); e != list_end (fd_list); e = list_next (e)) {
		filde = list_entry (e, struct file_des, elem);
		struct file_des *new_filde = (struct file_des *) malloc (sizeof (struct file_des));

		if (!new_filde) {
			free_flag = true;
			goto out;
		}

		*new_filde = *filde;

		if (new_filde->is_file == 2) {
			// file이 list에 있는지 찾는다.
			bool found_file = false; 
			for (int i = 0; i < lastIndex; i++) {
				if (oldfiles[i] == filde->file) {
					new_file = newfiles[i];
					found_file = true;
					break;
				}
			}
			//ASSERT(!found_file);
			if (!found_file) {
				new_file = file_duplicate (filde->file); // file_duplicate을 통해 file object를 복사한다.
				oldfiles[lastIndex] = filde->file;
				newfiles[lastIndex] = new_file;
				lastIndex += 1;
			}
			
		} else {
			new_file = NULL;
		}
		new_filde->file = new_file; 
		new_filde->is_file = filde->is_file;
		list_push_back (&current->fd_list, &new_filde->elem);	
	}
	ASSERT(list_size(&parent->fd_distinct_list) == lastIndex);

	for (int i = 0; i < lastIndex; i++) {
		struct dfile *dfile2 = (struct dfile *) malloc(sizeof(struct dfile));
		dfile2->file = newfiles[i];
		//printf("duplicate file : %d to %d", oldfiles[i], newfiles[i]);
		list_push_back(&current->fd_distinct_list, &dfile2->elem);
	}

	free(oldfiles);
	free(newfiles);



	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	succ = true; // successfully duplicated the resources.



out:

	aux->succ = succ;
	/* Give control back to the parent */
	if (succ){
		// parent?
		process_init (parent, &parent->sema_for_fork);
	}
	else{
		thread_current()->wait_on_exit = succ; // parent가 child가 끝날 때까지 기다리도록 한다.
		sema_up (&parent->sema_for_fork);
	}

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);

error:

 	thread_exit ();
}


/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
#ifdef VM
	// page table init 필요.. ?
	supplemental_page_table_init(&thread_current()->spt);
#endif

	/* And then load the binary */
	success = load (file_name, &_if); // fail on 0, success on 1

	/* If load failed, quit. */
	palloc_free_page (file_name);
	// if (!success)
	// 	return -1;
	// msg("DEBUG: process_exec success = %d", success);
	if (!success) {
		thread_current ()->exit_status = -1;
		thread_exit ();
	}

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}

struct thread *
get_child_by_id (struct thread *parent, tid_t tid) {
	struct list_elem *e;
	struct thread *t;

	lock_acquire (&parent->lock_for_child);

	for (e = list_begin (&parent->child_list); e != list_end (&parent->child_list);  e = list_next (e)) {
		t = list_entry (e, struct thread, child_elem);
		if (t->tid == tid){
			lock_release (&parent->lock_for_child);
			return t;
		}
	}
	// no child with tid found
	lock_release (&parent->lock_for_child);
	return NULL;
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// return -1;

	int ret = -1;
	struct thread *child = get_child_by_id (thread_current (), child_tid);

	if (child) {
		sema_down (&child->wait_sema);
		list_remove (&child->child_elem);
		ret = child->exit_status;
		sema_up (&child->exit_sema); 
	}

	return ret; // child가 없거나, 이미 wait한 경우
 
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	//msg("Process_exit called");
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	/* Free the file descriptors */
	struct list_elem *e;
	
	/*
	for (e = list_begin(&curr->fd_list); e != list_end(&curr->fd_list); e = list_next(e)) {
		struct file_des *filde_elem = list_entry (e, struct file_des, elem);
		struct list_elem *e2;
		if (filde_elem->file == NULL) { continue; }
		for (e2 = list_next(e); e2 != list_end(&curr->fd_list); e2 = list_next(e2)) {
			struct file_des *filde_elem2 = list_entry (e2, struct file_des, elem);
			if (filde_elem2->file == filde_elem->file) {
				filde_elem2->file = NULL;
			}
		}
	}	
	*/
	while (!list_empty (&curr->fd_distinct_list)) {
		e = list_begin (&curr->fd_distinct_list);
		struct dfile *dfile2 = list_entry (e, struct dfile, elem);
		file_close(dfile2->file);
		list_remove(e);
		free(dfile2);
	}
	while (!list_empty (&curr->fd_list)) {
		e = list_pop_front (&curr->fd_list);
		
		struct file_des *filde_elem = list_entry (e, struct file_des, elem);
		if (filde_elem) {
			// if (filde_elem->fd >= 2) {
			// 	if (true) {
			// 		// filde_elem->file->ref_count = 0;
			// 		file_close (filde_elem->file); 
			// 		// free (filde_elem);

			// 	}
			// 	else{
			// 		// filde_elem->file->ref_count--;
			// 	}
			// }
			// // if not file, just free the file descriptor
			free (filde_elem);
		}
	} 

	while (!list_empty (&thread_current ()->child_list)) {
		e = list_pop_front (&thread_current ()->child_list);
		struct thread *t = list_entry (e, struct thread, child_elem);
		t->wait_on_exit = false; // 바로 exit하도록 한다.
		// sema_down (&t->wait_sema);  // 이거 ?
		sema_up (&t->exit_sema); 
	}

	process_cleanup ();

	if (curr->executable)
		file_close (curr->executable);

	if (curr->wait_on_exit) {
		printf ("%s: exit(%d)\n", curr->name, curr->exit_status);
		sema_up (&curr->wait_sema);
		sema_down (&curr->exit_sema);
	}

}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	//msg("Process_cleanup called");
	supplemental_page_table_kill (&curr->spt);
	//msg("page table killed");
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;
	// msg("DEBUG: load start");

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;


	// msg("DEBUG: pml4_create success");
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	// msg("DEBUG: file read success");

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	// msg("DEBUG: load segment success");

	/* Set up stack. */
	if (!setup_stack (if_)){
		// msg("DEBUG: setup stack failed");
		goto done;
	}


	/* Argument Parsing */
	// 현재 file_name은 첫 공백이 null byte가 된 상태
	*(file_name + strlen(file_name)) = ' '; // 원래대로 되돌리기

	char *parse_name;
	char filename_new2[BUFFER];
	strlcpy(filename_new2, file_name, BUFFER-1);
	char filename_new3[BUFFER];
	strlcpy(filename_new3, file_name, BUFFER-1);
	
	/* Start address. */
	if_->rip = ehdr.e_entry; 


	success = true;

	// 여기에 추가. rsp를 바꿔야 한다. argument passing으로!
	// token이 몇 개 있지...? 길이는 얼마..?
	int argc = 0;
	int arglen = 0;
	char *token;
	for (token = strtok_r(filename_new2, " ", &parse_name);
	token != NULL; 
	token = strtok_r (NULL, " ", &parse_name)) { 
		argc += 1;
		arglen += (strlen(token) + 1);
	} 

	// rsp를 얼마나 내려야 하는가?
	// arglen + (argc + 2) * sizeof(char *) + alpha(8의 배수를 만들기 위한 align)
	while ((arglen % 8) != 0) { arglen += 1; }

	// if_->rsp는 uintptr = uint64 type. 따라서 그냥 그대로 빼준다.
	uintptr_t rsp_up = if_->rsp;
	if_->rsp = if_->rsp - arglen - (argc + 2) * 8;
	*((void **) if_->rsp) = NULL; // return address

	uintptr_t rsp_down = (if_->rsp) + 8;
	
	for (token = strtok_r(filename_new3, " ", &parse_name);
	token != NULL; 
	token = strtok_r (NULL, " ", &parse_name)) {
		//printf("token. ");
		rsp_up -= (strlen(token) + 1); 
		size_t s = strlcpy ((char *) rsp_up, token, strlen(token) + 1);
		//printf("argument is : %s\n", (char *) rsp_up);
		ASSERT (s == strlen(token));
		*((char **) rsp_down) = (char *) rsp_up;
		rsp_down += 8;
	} 
	//printf("Token complete. ");
	memset(rsp_down, 0, sizeof(void *));
	rsp_down += 8;
	ASSERT (rsp_up >= rsp_down);
	ASSERT (rsp_up - rsp_down < 8);
	while (rsp_up > rsp_down) {
		*((uint8_t *) rsp_down) = (uint8_t) 0;
		rsp_down += 1;
	}

	if_->R.rsi = (if_->rsp) + 8;
	if_->R.rdi = argc;

done:
 	/* We arrive here whether the load is successful or not. */
	if (success) {
		file_deny_write (file);
		t->executable = file;
	} else {
		file_close (file);
		t->executable = NULL;
	}
	/* We arrive here whether the load is successful or not. */
	// file_close (file);

	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

bool
lazy_load_segment (struct page *page, struct file_page *aux) { // static 지웟는데 문제없겟지
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	// struct file *file = NULL;

	// struct spt_copy_aux *load_info = (struct spt_copy_aux *)aux;
	// struct file_page *load_info = (struct file_page *)aux;

	struct file *file = aux->file;
	off_t offset = aux->ofs; 
	size_t read_bytes = aux->read_bytes;
	size_t page_zero_bytes = aux->zero_bytes;

	void *buffer = page->frame->kva; // 

	if (file == NULL) {

		return false;
	}

	//파일 위치를 찾기 위해
	file_seek(file, offset);
	
	// lock_acquire (&filesys_lock);
	//offset에 담긴 파일을 물리 프레임으로부터 읽어야함.
	off_t read_result = file_read(file, buffer, read_bytes);
	// lock_release (&filesys_lock);

	if (read_result!= read_bytes) { 
		// Lazy load 실패
		return false;
	} else {
		// read 성공. zero_bytes만큼 0으로 초기화
		memset(buffer + read_bytes, 0, page_zero_bytes); 
		return true;
	}

	NOT_REACHED (); // 디버깅
	return false;

}



/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		// void *aux = NULL;
		// lazy load segment을 위한 aux를 설정
		struct file_page *aux = (struct file_page *)malloc(sizeof (struct file_page));
		// copy members of load_info
		aux->file = file;
		aux->ofs = ofs;
		aux->read_bytes = page_read_bytes;
		aux->zero_bytes = page_zero_bytes;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux)) { 
			return false;
		}

		// edge case?

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		ofs += PGSIZE; // offset도 같이 이동해야한다.?
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */
	if (!is_user_vaddr(stack_bottom)){
		return success; // failed
	}

	if (!vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true)) { 
		// TODO: writable에 true 맞는지 확인
		// TODO: VM_MARKER_0이 맞는지 확인
		return success; // failed
	}
	if ( !vm_claim_page(stack_bottom)) {
	
		vm_dealloc_page(stack_bottom);
		return success; // failed
	} 
	if_->rsp = USER_STACK; // rsp를 USER_STACK으로 설정
	success = true;
	// msg("DEBUG: setup_stack success = %d", success);
	// msg("DEBUG: if_->rsp = %p", if_->rsp);
	// NOT_REACHED (); // 디버깅
	return success;
}
#endif /* VM */