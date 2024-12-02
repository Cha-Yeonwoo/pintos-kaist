/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "vm/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h" // filesys lock

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

	struct file_page *file_page = &page->file; // page가 어느 파일을 가리키는지 알기 위해 file_page를 사용

	file_page->file = NULL;         // 실제 파일은 나중에 설정됨
    file_page->ofs = 0;          // 파일 오프셋 초기화
    file_page->read_bytes = 0;      // 읽을 바이트 수 초기화
    file_page->zero_bytes = PGSIZE; // 초기화 바이트 수 설정

    // page->frame = NULL; // 아직 물리 메모리와 연결되지 않음

	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	// struct file_page *file_page UNUSED = &page->file;
	
	struct file_page *file_page = (struct file_page *) &page->file;

	 if (page == NULL || kva == NULL || page->operations->type != VM_FILE) {
        return false;
    }

    struct file_page *aux = (struct file_page *) page->uninit.aux; // uninit.aux에는 file_page가 들어있음?
    
    file_seek(aux->file, aux->ofs);
    if (file_read(aux->file, kva, aux->read_bytes) != (int)aux->read_bytes) {
        return false;
    }
    memset(kva + aux->read_bytes, 0, aux->zero_bytes); // zero_bytes만큼 0으로 초기화

   
    return true;



}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	// struct file_page *file_page UNUSED = &page->file;

	if (page == NULL || page->operations->type != VM_FILE) {
		return false;
	}

	struct file_page *file_page = &page->file;
    struct file *file = file_page->file;
    void *kva = page->frame->kva;


    struct file_page *aux = (struct file_page *) page->uninit.aux;

	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(aux->file, page->va, aux->read_bytes, aux->ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    } 

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;\
	if (pml4_is_dirty(thread_current()->pml4, page->va)) {
		;
	}
	// hash table에서 삭제하기
	hash_delete(&thread_current()->spt.pages_map, &page->hash_elem);

	if (page->frame != NULL) {
		free(page->frame);
	}
	page->frame = NULL;
}

/* Do the mmap */
void *
do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    struct thread *cur = thread_current();

    // 입력값 검증
    if (addr == NULL || pg_ofs(addr) != 0 || length == 0) {
        printf("DEBUG: Invalid address or length for mmap\n");
        return NULL;
    }

    // 파일 reopen
    struct file *reopen_file = file_reopen(file);
    if (reopen_file == NULL) {
        printf("DEBUG: Failed to reopen file for mmap\n");
        return NULL;
    }

    // 파일 길이 확인
    if (file_length(reopen_file) < offset) {
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
        size_t page_read_bytes = read_len > PGSIZE ? PGSIZE : read_len;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;
;
		struct file_page *aux = (struct file_page *) malloc(sizeof(struct file_page));
        if (aux == NULL) {
            // printf("DEBUG: Failed to allocate aux structure\n");
            file_close(reopen_file);
            return NULL; 
        }
        aux->file = reopen_file;
        aux->ofs = offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, aux)) {
            free(aux);
            file_close(reopen_file);
            return NULL;
        }

        read_len -= page_read_bytes;
        zero_len -= page_zero_bytes;
        offset += page_read_bytes;
        addr += PGSIZE;
    }

    return start_addr;
}





/* Do the munmap */
void
do_munmap (void *addr) {
	// addr가 NULL인지는 이미 munmap에서 확인함...
	if (addr == NULL) {
		return;
	}

	struct page *page = spt_find_page(&thread_current()->spt, addr);
	struct thread *cur = thread_current();

	if (page == NULL) {
		return;
	}
	
	// while (page != NULL && is_user_vaddr(page->va)) {
	// 	// TODO: clear and remove if necessary
	// 	struct file_page *file_page = &page->file; // 
    //     // struct file_page *file_page = page->uninit.aux;
    //     // 뭔가 file_page 제대로 못넘겨받는거 같은데...


	// 	if (pml4_is_dirty(page->page_thread->pml4, page->va)) {
    //         // 파일 기반 페이지인 경우
    //         if (page->operations->type == VM_FILE) {
    //             struct file *file = file_page->file;
    //             off_t offset = file_page->ofs;
    //             size_t write_bytes = file_page->read_bytes;

    //             // 파일에 데이터를 기록
    //             if (file != NULL) {
    //                 file_seek(file, offset);
    //                 if (file_write_at(file, page->frame->kva, write_bytes, offset) != (int)write_bytes) {
    //                     // printf("DEBUG: Failed to write dirty page to file\n");
	// 					;
	// 					return;
    //                 }
    //             }
    //         }
    //         // Dirty 플래그 초기화
    //         pml4_set_dirty(page->page_thread->pml4, page->va, false);
    //     }

	// 	pml4_clear_page(page->page_thread->pml4, page->va);
    //     // spt_remove_page(&cur->spt, page);

    //     // 다음 페이지로 이동
    //     addr += PGSIZE;
    //     page = spt_find_page(&page->page_thread->spt, addr); 


	// }
    // 다시 해보자...
    while (is_user_vaddr(addr)) {
        struct page *page = spt_find_page(&cur->spt, addr);
        if (page == NULL) {
            // printf("DEBUG: Invalid address %p during munmap\n", addr);
            break;
        }
        if (pml4_is_dirty(cur->pml4, page->va)) {
            // 적당히 write_at으로 처리하고
            // dirty flag를 clear해준다 (0으로)
            struct file_page *file_page = (struct file_page *)page->uninit.aux;
            file_write_at(file_page->file, addr, file_page->read_bytes, file_page->ofs);
            pml4_set_dirty(cur->pml4, page->va, 0);


        }

        pml4_clear_page(cur->pml4, page->va);
        spt_remove_page(&cur->spt, page); // 이게 필요했구나..?
        addr += PGSIZE;ㄴ
    }

}

