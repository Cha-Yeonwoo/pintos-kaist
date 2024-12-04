/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "vm/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h" // filesys lock

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);


bool lazy_load_segment_for_file (struct page *page, struct file_page *aux);

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

    struct file_page *file_page = (struct file_page *) page->uninit.aux;
    page->file.file = file_page->file;
    page->file.ofs = file_page->ofs;
    page->file.read_bytes = file_page->read_bytes;
    page->file.zero_bytes = file_page->zero_bytes;
    page->file.is_end = file_page->is_end;


	// struct file_page *file_page = &page->file; // page가 어느 파일을 가리키는지 알기 위해 file_page를 사용

	// file_page->file = NULL;         // 실제 파일은 나중에 설정됨
    // file_page->ofs = 0;          // 파일 오프셋 초기화
    // file_page->read_bytes = 0;      // 읽을 바이트 수 초기화
    // file_page->zero_bytes = PGSIZE; // 초기화 바이트 수 설정
    // file_page->is_end = true;

    // page->frame = NULL; // 아직 물리 메모리와 연결되지 않음

	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	
	// struct file_page *file_page = (struct file_page *) &page->file;

	 if (page == NULL || kva == NULL || page->operations->type != VM_FILE) {
        return false;
    }

    // struct file_page *aux = (struct file_page *) &page->file;
    // 그냥 넘겨주는게 아니라, 복사해서 file_read_at을 해야한다.
    
    struct file_page *aux = (struct file_page *) page->uninit.aux;

    aux->file = file_page->file;
    aux->ofs = file_page->ofs;
    aux->read_bytes = file_page->read_bytes;
    aux->zero_bytes = file_page->zero_bytes;
    aux->is_end = file_page->is_end;

    if (lazy_load_segment_for_file(page, aux) == false) {
        return false;
    }
    // //file_seek(aux->file, aux->ofs);
    // if (file_read_at(aux->file, kva, aux->read_bytes, aux->ofs) != (int)aux->read_bytes) {
    //     return false;
    // }
    // memset(kva + aux->read_bytes, 0, aux->zero_bytes); // zero_bytes만큼 0으로 초기화

    return true;

}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	// struct file_page *file_page UNUSED = &page->file;
    // msg("DEBUG: Swap out page at %p", page->va);

	if (page == NULL || page->operations->type != VM_FILE) {
        // msg("DEBUG: Failed check in file_backed_swap_out. %p", page->va);
		return false;
	}

	struct file_page *file_page = &page->file;
    struct file *file = file_page->file;
    void *kva = page->frame->kva;


    struct file_page *aux = &page->file;

	if (pml4_is_dirty(page->page_thread->pml4, page->va)) {
        file_write_at(aux->file, page->va, aux->read_bytes, aux->ofs);
        // file_seek(aux->file, file_page->ofs);
        pml4_set_dirty(page->page_thread->pml4, page->va, false);
    } 

    if (page->page_thread == NULL) { 
		msg("FATAL!!!!!");
	}

    pml4_clear_page(page->page_thread->pml4, page->va);

    page->frame = NULL; // clear the frame

    // Debug 
    // msg("DEBUG: Swap out page at %p", page->va);

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
    //("Destroy called");
	struct file_page *file_page UNUSED = &page->file;
    if (thread_current() == NULL) {
        //msg("thread null");
    }
    if (page->va == NULL) {
        //msg("va null");
    }
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        //msg("is dirty");
        struct file_page *aux = &page->file;
		file_write_at(aux->file, page->va, aux->read_bytes, aux->ofs);
        // file_seek(aux->file, file_page->ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
	} else {
        //msg("is not dirty");
    }
	// hash table에서 삭제하기
	hash_delete(&thread_current()->spt.pages_map, &page->hash_elem);

	// if (page->frame != NULL) {
	// 	free(page->frame);
	// }
	// page->frame = NULL;
    // file_close(file_page->file);
    // spt_remove_page(&thread_current()->spt, page); // 필요할까?
    // 그래도 뭔가 안지워지는듯한 느낌이 있으니
    page->frame = NULL;
    page->file.file = NULL;
    page->file.ofs = 0;
    page->file.read_bytes = 0;
    page->file.zero_bytes = 0;
    page->file.is_end = false;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    //msg("DEBUG: do_mmap called\n");
    struct thread *cur = thread_current();

    // 입력값 검증
    if (addr == NULL || pg_ofs(addr) != 0 || length == 0) {
        // msg("DEBUG: mmp fail %p %d", addr, length);
        return NULL;
    }

    if (is_kernel_vaddr(addr)){ // }) || is_kernel_vaddr(addr + length)) {
        // msg("DEBUG: mmap fail Kernel vaddr\n");
        return NULL;
    }

    if (length >= KERN_BASE) { 
        // msg("DEBUG: mmap fail length >= KERN_BASE  %d\n", length);
        return NULL; }

    if (pg_round_down(offset) != offset) {
        // msg("DEBUG : mmap fail offset is not page aligned %d\n", offset);
        return NULL;
    }

    // 파일 reopen
    // struct file *reopen_file = file_reopen(file);
    // if (reopen_file == NULL) {
    //     //printf("DEBUG: Failed to reopen file for mmap\n");
    //     return NULL;
    // }
    struct file *reopen_file = file;

    // 파일 길이 확인
    if (file_length(reopen_file) <= offset) {
        // printf("DEBUG: Offset exceeds file length\n");
        file_close(reopen_file);
        return NULL;
    }
    // TODO: offset이 valid한지도 체크해야함.

    size_t file_length_remaining = file_length(reopen_file) - offset;
    size_t read_len = file_length_remaining < length ? file_length_remaining : length;
    size_t zero_len = pg_round_up(length) - read_len;
    void *start_addr = addr;

    // 페이지 매핑
    while (read_len > 0 || zero_len > 0) {
        //msg("while loop in mmap\n");
        //msg("page map");
        size_t page_read_bytes = read_len > PGSIZE ? PGSIZE : read_len;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct file_page *aux = (struct file_page *) malloc(sizeof(struct file_page));
        if (aux == NULL) {
            // printf("DEBUG: Failed to allocate aux structure\n");
            //msg("file close\n");
            file_close(reopen_file);
            return NULL; 
        }
        aux->file = reopen_file;
        aux->ofs = offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        read_len -= page_read_bytes;
        zero_len -= page_zero_bytes;
        offset += page_read_bytes;

        aux->is_end = false;
        if ((read_len == 0) && (zero_len == 0)) { aux->is_end = true; }

        // unique.k 12031003
        // 그냥 lazy_load_segment를 넣으면 안되고, lazy_load_segment를 하되 page를 file page로 설정해주는 작업이 추가로 필요. 
        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment_for_file, aux)) {
            //msg("alloc fail\n");
            free(aux);
            file_close(reopen_file);
            return NULL;
        }

        
        addr += PGSIZE;
    }

    return start_addr;
}

bool lazy_load_segment_for_file (struct page *page, struct file_page *aux) {
    // page->file.file = aux->file;
    // page->file.ofs = aux->ofs;
    // page->file.read_bytes = aux->read_bytes;
    // page->file.zero_bytes = aux->zero_bytes;
    // page->file.is_end = aux->is_end;
    return lazy_load_segment(page, aux);
}



/* Do the munmap */
void
do_munmap (void *addr, bool delhash) {
    // file이 어디까지임?

	// addr가 NULL인지는 이미 munmap에서 확인함...
    //msg("unmap called");
    //msg("munmap called\n");
    //printf("do_unmap callled!!!");
	if (addr == NULL) {
        //msg("addr is null");
        //msg("null addr \n");
		return;
	}

	struct page *page = spt_find_page(&thread_current()->spt, addr);
    
	struct thread *cur = thread_current();

	if (page == NULL) { return; }
    struct file *file = page->file.file;

    while (1) {
        struct page *page = spt_find_page(&cur->spt, addr);
        if (page == NULL) {
            break;
        }
        if (pml4_is_dirty(cur->pml4, page->va)) {
            struct file_page *file_page = &page->file;
            file_write_at(file_page->file, addr, file_page->read_bytes, file_page->ofs);
            pml4_set_dirty(cur->pml4, page->va, 0);
        }

        bool is_end = page->file.is_end;

        pml4_clear_page(cur->pml4, page->va);
        //msg("clearing page finished.");
        if (delhash) { hash_delete (&thread_current()->spt.pages_map, &page->hash_elem); } // 이게 필요했구나..? 
        // if (delhash) { spt_remove_page(&cur->spt, page); } // 이게 필요했구나..? 
        // page에 해당하는 frame이 있으면, 이것은 모두 해제 처리.
        // destroy 수순을 밟는다. 
        if (page->frame != NULL) {
            palloc_free_page(page->frame->kva);
            list_remove(&page->frame->elem);
            free(page->frame);
            page->frame = NULL;
            free(page); // 여기..!
            // page를 free하는 것과 list_remove를 하는거가 같이 다녀야함.
            // 안그러면 mmap-merge 관련 테케에서 문제가 발생함.
        }

        // free(page); // 요거를 위로 올림


        //msg("removing page finished.");
        addr += PGSIZE;
        if (is_end) { 
            //msg("breaking normally\n");
            file_close(file);
            break;
        }
    }

}

