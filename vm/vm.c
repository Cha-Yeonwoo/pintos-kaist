/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include "threads/mmu.h"
#include <list.h>

struct list frame_table; /* The frame table. */
struct lock frame_lock; // 필요하려나? 

/* Helper */
int spt_hash (const struct hash_elem *elem, void *aux);
bool cmp_spt (const struct hash_elem *a, const struct hash_elem *b, void *aux);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init (&frame_table); // Initialize frame table
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		struct page *new_page = (struct page *) malloc (sizeof (struct page));
		if (new_page == NULL) return false;

		// 서로다른 initializer를 사용하여 new_page를 초기화
		if (VM_TYPE(type) == VM_ANON) { // anonymous page
			uninit_new(new_page, upage, init, type, aux, anon_initializer);
		} 
		else if (VM_TYPE(type) == VM_FILE) {
			uninit_new(new_page, upage, init, type, aux, file_backed_initializer);
		} 
		else { // vm type is VM_PAGE_CACHE
			;
			// lazy load ?

		}

		new_page->writable = writable;
		// 또 복사할 member가 있을까?

		// msg("DEBUG: vm_alloc_page_with_initializer %p", new_page);
		/* TODO: Insert the page into the spt. */
		return spt_insert_page (spt, new_page); // insert page into spt
		
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = (struct page *) malloc (sizeof (struct page));
	struct page *page_start;
	// 주어진 va를 이용해서 page를 찾아야한다
	page_start->va = pg_round_down(va);

	// 현재 thread에서 찾아오는게 맞다... 
	// 그치만 이미 vm_alloc_page_with_initializer에서 thread_current()로 호출하고 있음
	struct hash_elem *e = hash_find(&(spt->pages_map), &(page_start->hash_elem)); // spt에서 page를 찾아온다

	if (e==NULL){
		return NULL; // page가 없으면 NULL을 반환
	}
	page = hash_entry(e, struct page, hash_elem);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	struct hash_elem *elem = hash_insert(&(spt->pages_map), &(page->hash_elem)) ;
	// hash_insert는 성공하면 NULL을 반환한다.
	// 실패하면 이미 있는 elem을 반환한다.
	// msg("DEBUG: hash inserted in spt_insert_page %p", elem);
	if (elem == NULL){
		succ = true; 
	}

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {

	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	 // 어떤 policy로 evict할지 정해야한다

	  if (list_empty(&frame_table)) {
		return;
	 }

	 //return list_entry(list_begin(&frame_list), struct frame, elem);

	 
	 struct list_elem *frame;
	 victim = list_entry(list_begin(&frame_table), struct frame, elem);
	// 일단 무지성으로 맨앞에꺼 꺼내오는중.. 
	// TODO: instruction 다시 읽고 어떤 frame을 evict할지 구현
	return victim;

}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	if (swap_out(victim->page)){
		return victim;
	}
	else{
		return NULL; 
	}

}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL; 
	/* TODO: Fill this function. */
	frame = (struct frame *) malloc (sizeof (struct frame));
	if (frame == NULL) return NULL;

	frame->kva = palloc_get_page(PAL_USER);
	
	if (frame->kva == NULL){ // palloc_get_page가 실패했을 때
		frame = vm_evict_frame(); // evict frame을 호출해서 frame을 얻어온다
		frame->page = NULL; // 일단 assertion 에러 안나게 하려고 넣은거
	}
	else{
		frame->page = NULL; // 일단 assertion 에러 안나게 하려고 넣은거
		list_push_back(&frame_table, &frame->elem);	
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *adjusted_addr = pg_round_down(addr);
	
	// 일단 stack growth가 가능한지 체크
	// rsp 관련도 필요할까?
	const uint64_t STACK_SIZE = 0x100000; // 1MB
	if (addr < USER_STACK && addr > (USER_STACK - STACK_SIZE) ) {
		// stack size가 너무 커서 할당이 불가능한 경우
		return;
	}


	bool alloc_succ = vm_alloc_page(VM_ANON | VM_MARKER_1, adjusted_addr, true); // stack page 생성
	if (alloc_succ) { 
		struct page *pg = spt_find_page(&thread_current()->spt, adjusted_addr);
        vm_claim_page(adjusted_addr);
        adjusted_addr += PGSIZE;
		alloc_succ = vm_alloc_page(VM_ANON | VM_MARKER_1, adjusted_addr, true);
	}

}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	//printf("handle fault addr: 0x%x\n", addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	bool succ= true;
	
	// bad addr
	if (addr == NULL) {
		return false;
	}
	if (is_kernel_vaddr(addr) && user || !not_present) {
		return false;
	} 
	
	// rsp 포인터를 가져와서 stack growth를 할지 말지 결정
	void *pointer = f->rsp;


	page = spt_find_page(spt, addr);
	if (page == NULL) {	//스택이 가득차서 할당이 더 이상 불가능한 경우

		// asm volatile("movq %%rsp, %0" : "=r" (pointer)); // rsp를 pointer에 저장
		vm_stack_growth(addr); // stack을 확장시킨다
	} else {
		if (write && page->writable == false) {
			// 읽기 전용 페이지에 쓰려고 할 때
			succ= false;
		} 
		else {
			return vm_do_claim_page(page);
		}
	}

	
	return succ;

    // NOT_REACHED ();
	// return vm_do_claim_page (page);
	// return true; // 무작정 true 리턴하면?

}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page != NULL) {
		// msg("DEBUG: vm_claim_page %p", page);
		return vm_do_claim_page (page);
	} else {
		return false;
	}

	// return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (frame == NULL) {
		// msg("DEBUG: vm_get_frame failed in vm_do_claim_page");
		return false;
	}
	
	// 위에서 갖고온 frame을 page table에 넣어 업데이트
	// swap in이 가능한 경우? 

	if (pml4_set_page (thread_current()->pml4, page->va, frame->kva, page->writable) ){ 	
			return swap_in(page, frame->kva);
		
	}
	else{
		return false;
	}
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	// pages_map을 초기화
	hash_init(&(spt->pages_map), spt_hash, cmp_spt, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	// src -> dst
	struct hash_iterator spt_iterator; // src의 spt를 iterate하기 위한 iterator

	hash_first(&spt_iterator, &(src->pages_map));  // src의 spt의 첫번째 page부터 시작

	while(hash_next(&spt_iterator)) {
		struct page *src_page = hash_entry(hash_cur(&spt_iterator), struct page, hash_elem);
		//vm_alloc에서 보이다시피 vm_type, upage, writable, init, aux 정보들을 다 담아서 dst spt안에 넣어줘야한다
		enum vm_type src_page_type = src_page->operations->type;

		if (src_page_type == VM_ANON) {

			if (!vm_alloc_page(src_page_type, src_page->va, src_page->writable)) return false;

			if (!vm_claim_page(src_page->va)) return false; // 


			struct page *dst_page = spt_find_page(dst, src_page->va); // dst에 해당 page가 있는지 확인
			if (dst_page == NULL)  return false; // dst에 해당 page가 없으면 false
			
		
			memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE); // src의 frame을 dst의 frame에 복사
		} 
		else if (src_page_type == VM_UNINIT) {
			// VM_UNINIT인 경우에는 aux를 복사해서 initializer를 사용해서 page를 생성
			if (src_page->uninit.type == VM_ANON) { // VM_ANON일 경우, aux를 복사해서 initializer를 사용해서 page를 생성
							
				void *src_aux = (struct spt_copy_aux *) malloc(sizeof(struct spt_copy_aux)); // aux를 복사하기 위한 공간 할당
				memcpy(src_aux, src_page->uninit.aux, sizeof(struct spt_copy_aux));  // uninit은 void * aux를 가지는데, 이것을 이용하면 될 것 같다.

				// page에 맞는 initializer를 사용
				if (!vm_alloc_page_with_initializer(VM_ANON, src_page->va, src_page->writable, src_page->uninit.init, src_aux)) {
					return false;
				}
			}

		}
		else {
			; // VM_FILE, VM_PAGE_CACHE인 경우는 일단 무시
		}
	}
	return true; // 여기까지 왔으면 성공적으로 copy가 된 것
	
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&(spt->pages_map), NULL);	
}


/* Helper */
// hash_elem을 비교하는 함수
bool cmp_spt (const struct hash_elem *a, const struct hash_elem *b, void *aux) {
	const struct page *pa = hash_entry(a, struct page, hash_elem);
	const struct page *pb = hash_entry(b, struct page, hash_elem);

	return pa->va < pb->va;
}

int spt_hash (const struct hash_elem *elem, void *aux) {
	const struct page *p = hash_entry(elem, struct page, hash_elem);
	return hash_bytes(&p -> va, sizeof(p->va));
}
