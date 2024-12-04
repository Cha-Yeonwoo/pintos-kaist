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

#include "vm/vm.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void *mmap(void *addr, size_t length, bool writable, int fd, off_t offset);
void munmap(void *addr);



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
	const struct file_des *fdb = list_entry (b, struct file_des, elem);

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
	void *ptr = pg_round_down (p); // 페이지 명시
	for (; ; ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		if (pte == NULL || is_kern_pte(pte)) // page가 없거나 커널 페이지 테이블이면
			return true;

		// 마지막 Null인지 확인
		if (strlen (p) < PGSIZE) {
			if (strchr (p, '\0') != NULL)
				return false;
			else
				return true;
		}
		
	}
	return false;
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

bool create(struct intr_frame *f) {

	char *file_name = (char *) f->R.rdi;
	unsigned initial_size = f->R.rsi;
	bool ret = false;

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

bool remove(struct intr_frame *f) {
	char *file = (char *) f->R.rdi;
	bool ret = false;
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
		file = filesys_open(file_name); // 파일을 열 때 calloc이 안에서 실행됨
		if (file) {
			filde = (struct file_des *) malloc (sizeof (struct file_des));
			struct dfile *dfile = (struct dfile *) malloc (sizeof (struct dfile));
			if ((filde != NULL) && (dfile != NULL)) {
				ret = fd;
				filde->fd = ret;
				filde->file = file;
				filde->is_file = 2;
				list_insert_ordered (&t->fd_list, &filde->elem, fd_sort, NULL);
				dfile->file = file;
				//printf("open file : %d", file);
				list_push_back(&t->fd_distinct_list, &dfile->elem);
			} else {
				free(filde);
				free(dfile);
				file_close (file); // 보통은 file_close에서 free가 된다.
			}
				
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
	if (filde) ret = file_length (filde->file); // get the file length

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
		// msg("DEBUG: read buf is invalid");
		thread_exit ();
		return -1;
	}
	// buffer에 쓰다가 침범하는지를 확인하기 위해 size adjust
	if (is_kernel_vaddr (buf + size)){
		size  -= (size_t)((buf + size) - KERN_BASE);
	}

#ifdef VM
	if (spt_find_page(&cur->spt, (void*)buf) != NULL && spt_find_page(&cur->spt, (void*)buf)->writable == 0){ 
		// msg("DEBUG: read page is not valid");
		cur->exit_status = -1;
		//printf("%s: exit(%d)\n", cur->name, cur->exit_status);
		thread_exit ();
		return -1;
	}
#endif


	ptr = pg_round_down (buf);
	for (; ptr <= pg_round_down (buf + size-1); ptr += PGSIZE) { // 등호?
		// msg("DEBUG: read ptr = %p", ptr);
		// 여기서 read boundary 뿐만 아니라 다른 테스크들도... 걸림

	
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		if (pte == NULL ){ // || is_kern_pte(pte) 
			cur->exit_status = -1;
			// msg("DEBUG: read pte is invalid, %p", ptr);
			// 몇몇 케이스들의 paraent가 여기서 걸린다...


		
			thread_exit ();
			return -1;
		}

	}
		
	// msg("DEBUG: read size = %d", size);

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde) {
		if (filde->is_file == 0) {
			for (; read_bytes < size; read_bytes++)
				buf[read_bytes] = input_getc ();

		}
		else if (filde->is_file == 1) {
			// msg("DEBUG: read from console");
			ret = -1;

		}
		else{ // FILE
			ret = file_read (filde->file, buf, size);
			// msg("DEBUG: read from file, %d", ret);
			// buffer에 적다가 페이지 넘어가면? 새로운 페이지 할당.

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

	// if (fd != 1) {
	// 	msg("write called. fd value is %d", fd);
	// }

	void *ptr;
	// check the buffer is valid
	if (buf == NULL || !is_user_vaddr (buf)){
		cur->exit_status = -1;
		// if (fd != 1) {
		// 	msg("write exit 0");
		// }
		thread_exit ();
		return -1;
	}

	ptr = pg_round_down (buf); 

	for (; ptr <= pg_round_down (buf + size); ptr += PGSIZE) {
		uint64_t *pte = pml4e_walk (cur->pml4, (uint64_t) ptr, 0);
		// check the page is valid
		if (pte == NULL ||is_kern_pte(pte)){
			// if (fd != 1) {
			// 	if (pte == NULL){
			// 		msg("write exit 1");
			// 	} else if (is_kern_pte(pte)) {
			// 		msg("write exit 2");
			// 	}
			// }
			cur->exit_status = -1;
			thread_exit ();
			return -1; // 걸쳐있으면 바로 종료
		}
	}
	// if (fd != 1) {
	// 	msg("write called another. fd value is %d", fd);
	// }

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde) {
		if (filde->is_file == 0) {
			// cannot write to stdin
			lock_release (&filesys_lock);
			return -1;
		}
		else if (filde->is_file == 1) {
			putbuf (buf, size);  // write to console
			ret = size;
		}
		else{
			// TODO: writing should be possible when opened even if the file is deleted.


			ret = file_write (filde->file, buf, size); // write to file
		}
	}
	// filde is NULL -> error
	lock_release (&filesys_lock);
	// if (fd != 1) {
	// 	msg("write finished. return value is %d", ret);
	// }
	return ret;
}


void seek (struct intr_frame *f) {
	struct file_des *filde;
	int32_t fd = f->R.rdi;
	unsigned position = f->R.rsi; // position to seek


	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);
	if (filde && (filde->is_file == 2))
		file_seek (filde->file, position);
	lock_release (&filesys_lock);

	return;
}

int tell (struct intr_frame *f) {
	int fd = f->R.rdi;
	struct file_des *filde;
	int ret = -1;

	lock_acquire (&filesys_lock);
	filde = find_filde_by_fd (fd);

	if (filde && (filde->is_file == 2))
		ret = file_tell (filde->file);
	lock_release (&filesys_lock);
	return ret;
}



int close (int fd, bool lock) {
	struct thread *cur = thread_current();
    struct list_elem *e;

	int ret = -1;

	if (lock) { lock_acquire(&filesys_lock); }
	struct file_des *filde = find_filde_by_fd(fd);

	if (filde) {
		//printf("we want to close %d\n", filde->file);
		if (filde->is_file < 2) {
			struct list_elem curr_elem = filde->elem;
			list_remove(&curr_elem);
			free(filde);
			if (lock) lock_release(&filesys_lock);
			return 0;
		}
		struct file *curr_file = filde->file;
		int count = 0;
		for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = list_next(e)) {
			struct file_des *filde2 = list_entry(e, struct file_des, elem);
			if (filde2->file == filde->file) { count += 1; }
		}
		ASSERT(count >= 1)
		if (count == 1) {
			bool found = false;
			struct dfile *dfile2;
			for (e = list_begin(&cur->fd_distinct_list); e != list_end(&cur->fd_distinct_list); e = list_next(e)) {
				dfile2 = list_entry(e, struct dfile, elem);
				if (dfile2->file == filde->file) { 
					found = true; 
					break;
				}
			}
			//printf("file %d is deleted.\n", filde->file);
			ASSERT(found);
			list_remove(e);
			free(dfile2);
			file_close(curr_file); // close하면 free됨
		}

		struct list_elem curr_elem = filde->elem;
		list_remove(&curr_elem); // remove the file descriptor from the list

		free(filde); // free the file descriptor
		ret = 0; //success
	}
	if (lock) lock_release(&filesys_lock);
	return ret;


}

int dup2(int oldfd, int newfd){ 
	//printf("dup2 : %d, %d\n", oldfd, newfd);
	// copy the file descriptor
	struct thread *cur = thread_current();
	struct file_des *old_filde;
	struct file_des *new_filde;
	int ret = -1;

	if (oldfd == newfd) // same file descriptor. no need to copy
		return newfd;

	lock_acquire (&filesys_lock);
	old_filde = find_filde_by_fd (oldfd);

	if (old_filde) {
		new_filde = find_filde_by_fd (newfd);
		if (new_filde) {
			// should copy the file descriptor
			// TODO: should clean the old file descriptor
			/*
			if (new_filde->fd >= 2) {
				file_close (new_filde->file); // close (and free) the file
				new_filde->file = old_filde->file;
				new_filde->is_file = old_filde->is_file;
				ret = newfd; // return the new file descriptor
			}
			lock_release (&filesys_lock);
			return ret;
			*/
			//printf("dup2-close. new_filde is %d, newfd is %d.\n", new_filde, newfd);
			close(newfd, false);
		}
		// new_filde 못찾았을 때
		new_filde = (struct file_des *) malloc (sizeof (struct file_des));
		if (new_filde) {
			// *new_filde = *old_filde; // copy the file descriptor
			new_filde->fd = newfd;
			new_filde->is_file = old_filde->is_file;
			new_filde->file = old_filde->file;
			if (list_size (&cur->fd_list) < 128){  // file descriptor의 한도는 128?
				list_insert_ordered (&cur->fd_list, &new_filde->elem, fd_sort, NULL);
				ret = newfd;
			}
			else{
				free (new_filde);
			}
		}
		else{
			// new_filde가 없을 때

		}
	}
	lock_release (&filesys_lock);
	return ret;
}


/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// msg("DEBUG: syscall_handler. syscall number: %d", f->R.rax);
	// f-R.rax: system call number (syscall-nr.h)
	// f 를 thread 안에 넣는다??

	// 여기에 thread의 rsp 저장해야함
#ifdef VM
	thread_current()->rsp = (void *) f->rsp;
#endif

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
			seek (f);
			break;
		case SYS_TELL:
			f->R.rax = tell (f);
			break;
		case SYS_CLOSE:
			f->R.rax = close ((int) f->R.rdi, true);
			break;
		case SYS_DUP2:
			f->R.rax = dup2 (f->R.rdi, f->R.rsi);
			break;
		case SYS_MMAP:
			f->R.rax = (uint64_t)mmap((void *) f->R.rdi, (size_t) f->R.rsi, (int) f->R.rdx, (int) f->R.r10, (off_t) f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap((void *) f->R.rdi);
			break;
		default:
			printf ("Unexpected Syscall: %llx", f->R.rax);
			f->R.rax = -1;
			break;
	}
 }


 /* Project 3 */

void *mmap(void *addr, size_t length, bool writable, int fd, off_t offset){
	// TODO: implement mmap
	struct thread *cur = thread_current();
	struct file_des *filde;
	struct file *file;
	off_t ofs;
	size_t page_read_bytes; // page에서 읽어야 하는 바이트 수
	size_t page_zero_bytes; // page에서 0으로 채워야 하는 바이트 수
	bool success = true;

	// addr을 리턴하는 함수임
	// 실패하면 -1이 아니라 NULL을 리턴해야함.. 당연함...

	if (length <= 0 || pg_ofs(addr) != 0 || addr == NULL || fd < 2) {
		return NULL;
	}

	length = (size_t) pg_round_up((void *) length); // length를 페이지 크기의 배수로 만들어야 함.

	// if (spt_find_page(&cur->spt, addr) != NULL) {
	// 	// already mapped
	// 	return NULL;
	// }
	for (int i = 0; i < length; i += PGSIZE) {
		//  for already mapped cases
		// 어짜피 addr round down하는데 for문을 돌려야 하는 이유가 있나?
        if (spt_find_page(&cur->spt, addr + i) != NULL) {
            return NULL;
        }
    }

	filde = find_filde_by_fd(fd);
	if (filde == NULL || filde->file == NULL) {
		// msg("DEBUG : file descriptor is not valid");
		return NULL;
	}

	file = file_reopen(filde->file);

	if (file_length(file) == 0) {
		// msg("DEBUG : file length is 0");
		return NULL;
	}

	if (file_length(file) <= offset) {
		// msg("DEBUG : file length is smaller than offset");
		return NULL;
	}

	if (file == NULL) {
		// reopen 실패
		msg("DEBUG : file reopen failed");
		return NULL;
	}
	
	void *result = do_mmap(addr, length, writable, file, offset);
	if (result == NULL) {
		file_close(file); // 실패 시 파일 닫기
		return NULL;
	}
	return result; // 성공 시 addr 리턴

}


void munmap(void *addr){
	//msg("unmap called!!!!!!");
	// struct thread *cur = thread_current();

	// if (addr == NULL) {
	// 	return;
	// }

	// if (!spt_find_page(&cur->spt, addr)) {
	// 	// not mapped
	// 	return;
	// }
	do_munmap(addr, true);

}