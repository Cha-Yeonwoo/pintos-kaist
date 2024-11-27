/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "vm/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct file *reopen_file = file_reopen(file); // reopen file
	if (reopen_file == NULL) {
		return NULL;
	}
	// 이것도 주소 리턴임. 에러시 -1 아니고 NULL임

	size_t read_len = length;
	size_t zero_len = 0;
	if (file_length(reopen_file) < offset + length) {
		return NULL;
	}
	else {
		read_len = file_length(reopen_file) - offset;
	}

	/* Check the range */
	if (addr == NULL || length == 0) {
		return NULL;
	}



	// if(!vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_backed_initializer, reopen_file)){
	// 	return -1;
	// }
	while (read_len + zero_len> 0) {
		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_backed_initializer, reopen_file)) {
			return NULL;
		}
		if (read_len > PGSIZE) {
			struct spt_copy_aux *aux = (struct spt_copy_aux *) malloc(sizeof(struct spt_copy_aux));
			aux->page_file = reopen_file;
			aux->offset = offset;
			aux->read_bytes = PGSIZE;
			aux->zero_bytes = zero_len;

			if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_backed_initializer, aux)) {
				return NULL;
			}

			read_len -= PGSIZE;
			offset += PGSIZE;
			addr += PGSIZE;
		}
		else {
			// PGSIZE보다 작은 경우
			zero_len = PGSIZE - read_len;
			struct spt_copy_aux *aux = (struct spt_copy_aux *) malloc(sizeof(struct spt_copy_aux));
			aux->page_file = reopen_file;
			aux->offset = offset;
			aux->read_bytes = read_len;
			aux->zero_bytes = zero_len;

			if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, file_backed_initializer, aux)) {
				return -1;
			}
			read_len = 0;
			zero_len = 0;
			addr += PGSIZE;

			
		}
		addr += PGSIZE;
		read_len -= PGSIZE;
	}
	return addr;

}



/* Do the munmap */
void
do_munmap (void *addr) {
	struct page *page = spt_find_page(&thread_current()->spt, addr);
	if (page == NULL) {
		return;
	}
	while (page != NULL) {
		struct spt_copy_aux *aux = (struct spt_copy_aux *) page->uninit.aux;

		if (pml4_is_dirty(thread_current()->pml4, page->va)) { // dirty page
			file_write_at(aux->page_file, page->va, PGSIZE, aux->offset);
			pml4_set_dirty(thread_current()->pml4, page->va, false);
		}
		
		pml4_clear_page(thread_current()->pml4, page->va);
		addr += PGSIZE; // move to next page
		page = spt_find_page(&thread_current()->spt, addr);
		
		// if (page->operations->type == VM_FILE) {
		// 	if (page->frame != NULL) {
		// 		file_backed_swap_out(page);
		// 	}
		// 	spt_remove_page(&thread_current()->spt, page);
		// }
		// page = spt_find_page(&thread_current()->spt, addr);
	}

}

