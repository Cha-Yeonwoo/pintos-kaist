/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "bitmap.h"
#include "threads/synch.h"

struct lock swap_lock; // lock for swap table

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

// Define a swap table
struct bitmap *swap_table; 

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* TODO: Set up the swap_disk. */
	// swap_disk = NULL;


	// bitmap을 초기화
	swap_disk = disk_get(1, 1); // get the swap disk
	swap_table = bitmap_create(disk_size(swap_disk) / 8);
	if (swap_table == NULL) {
		msg("Failed to create a swap table.");
		// error
	}
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;

	anon_page->swap_index = -1; // initialize the swap index. 0 아니구 -1로 초기화

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;


	if (!bitmap_test(swap_table, anon_page->swap_index)) {
		return false;
	}
	bitmap_reset(swap_table, anon_page->swap_index); // reset the bitmap
	size_t sector_idx = anon_page->swap_index * 8; // get the sector index

	for (int i = 0; i < 8; i++) {
		disk_read(swap_disk, sector_idx + i, kva + i * DISK_SECTOR_SIZE); // read the contents from the swap disk
	}

	page->frame->kva = kva;
	page->frame->page = page;

	return true;

}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	size_t swap_index = bitmap_scan(swap_table, 0, 1, false); // find a free swap slot
	if (swap_index == BITMAP_ERROR) {
		return false;
	}

	void *kva = page->frame->kva;
	size_t sector_idx = swap_index * 8; // get the sector index
	for (int i = 0; i < 8; i++) {
		disk_write(swap_disk, sector_idx + i, kva + i * DISK_SECTOR_SIZE); // write the contents to the swap disk
	}

	bitmap_mark(swap_table, swap_index); // mark the bitmap

	anon_page->swap_index = swap_index; // set the swap index

	
	// pml4_clear_page(thread_current()->pml4, page->va); // clear the page table entry
	// pml4_set_dirty(thread_current()->pml4, page->va, false); // clear the dirty bit
	pml4_clear_page(page->page_thread->pml4, page->va); // clear the page table entry

	page->frame = NULL; // clear the frame

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
	if (page->frame != NULL) {
		list_remove(&page->frame->elem);
		free(page->frame);
		page->frame = NULL;
	}
}
