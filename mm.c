/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "Bernadette<3",
    /* First member's full name */
    "Nathan PELUSO",
    /* First member's email address */
    "nathan.peluso@polytechnique.edu",
    /* Second member's full name (leave blank if none) */
    "Vibhakar SIVAKUMAR",
    /* Second member's email address (leave blank if none) */
    "vibhakar.sivakumar@polytechnique.edu"
};

#define DEBUG 0


/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define WORD_SIZE 4
#define DSIZE 8
#define CHUNK_SIZE 6*ALIGNMENT 
#define MINBLOCKSIZE 4*WORD_SIZE // min size is HEADER_SIZE + FOOTER_SIZE + 2*WORD_SIZE = 4*WORD_SIZE(we have to keep some space for next & prev pointers)
/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define READ(p)  (*(unsigned int*)(p)) 
#define WRITE(p,x)  (*(unsigned int*)(p)=(x))

#define HEADER_SIZE WORD_SIZE // WARNING : This size corresponds to a ALLOCATED BLOCK
#define FOOTER_SIZE WORD_SIZE

#define MAX(x, y) ((x) > (y)? (x) : (y))
#define MIN(x, y) ((x) > (y)? (y) : (x))

#define HDR(block)  ( ((char*) block - WORD_SIZE))  //Returns address of the header of a given block
#define PACK(size,is_allocated) (size | is_allocated) // Sizes are a multiple of Alignment (8) : we can use the parity bit to store the is_allocated boolean 
#define GET_SIZE(block) ( READ(HDR(block)) & ~0x7)
#define GET_ALLOCATED(block) ( READ(HDR(block)) & 0x1)
#define GET_SIZE_HERE(p) ( READ(p) & ~0x7)
#define GET_ALLOCATED_HERE(p) ( READ(p) & 0x1)
#define FTR(block)  ( IS_BOUND(block) ? block : ((char*) (block) + GET_SIZE(block)))  //Returns address of the footer of a given block

#define NEXT_BLOCK(block) (FTR(block)+2*WORD_SIZE)
#define PREV_BLOCK(block) ((void *)(block) - GET_SIZE_HERE(block - 2*WORD_SIZE)-2*WORD_SIZE)

#define NEXTFREE(block) (*(void **) block) // Address of the next free block (beginning of block = next.next)
#define PREVFREE(block) (*(void **) (block+WORD_SIZE)) // Address of the prev free block (beginning of block = prev.next)

#define IS_PROLOGUE(block) ((void*) block<=mem_heap_lo()+WORD_SIZE)
#define IS_EPILOGUE(block) (mem_heap_hi()+1-WORD_SIZE<=(void*) block)
#define IS_BOUND(block) (IS_PROLOGUE(block) || IS_EPILOGUE(block))

/*
 * Layout of a free block, size N=k*ALIGNMENT (size is given for an allocated block)
 *  
 *  [HEADER'][ char[N-2] ][FOOTER]
 * Where :
 *  [HEADER'] = [ PACK( (unsigned int)N , (bit) allocated) ) ] [ (unsigned int*) next ] [ (unsigned int*) prev]
 *            = [HEADER]                                       [ (unsigned int*) next ] [ (unsigned int*) prev]
 *  [FOOTER] = [ PACK( (unsigned int)N , (bit) allocated) ) ]
 * 
 * As prev and next are only used for a free block, we can write over them once the block is allocated
 * 
 * Layout of an allocated block, size N=k*ALIGNMENT
 *  [ PACK( (unsigned int)N , (bit) allocated) ) ][ char[N] ][ PACK( (unsigned int)N , (bit) allocated) ) ]
 * 
 * In the following code, the convention is :
 *  - 'block' : pointer to block data : points just after the size&allocated bit 
 * So if the block is allocated this points to the first data word, else it points to the 'prev' pointer.
 * 
 *  - 'p' : pointer to the block structure : points to the header
 */

/* Header shape : [(unsigned int) size] */
/* Footer shape : [(unsigned int) size] */


// Private variables represeneting the heap and free list within the heap
static char *heap = 0;  /* Points to the start of the heap */
static char *free_list = 0;  /* Points to the frist free block */


static void *extend_heap(size_t words);
static void place(void *block, size_t asize);
static void remove_free_block(void *block);
static void *find_fit(size_t size);
static void *coalesce(void *block);

static void displayBlock(void* block);
static void displayHeap(int verbose);

static int checkBlock(void * block);
static int checkFreeList();
static int checkFreeInFreeList(void* block);
static int checkHeap();


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap = mem_sbrk(2*WORD_SIZE + HEADER_SIZE+FOOTER_SIZE+CHUNK_SIZE)) == (void *)-1) // +2 due to prologue and epilogue header/footer
    {
        return -1;
    }
    WRITE(heap + (0*WORD_SIZE), PACK(0,1)); // Prologue header
    WRITE(heap + (1*WORD_SIZE), PACK(CHUNK_SIZE,0)); // Size and is_allocated
    WRITE(heap + (2*WORD_SIZE), -1); // No prev
    WRITE(heap + (3*WORD_SIZE), -1); // No next
    heap+=2*WORD_SIZE;
    WRITE(FTR(heap),PACK(CHUNK_SIZE,0)); // Size and is_allocated
    WRITE(FTR(heap)+WORD_SIZE,PACK(0,1)); // Epilogue header
    free_list=heap;
    // displayHeap(1);
    // checkHeap();
    // checkFreeList();
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    if (DEBUG)
    	printf("MALLOC START\n");
	
    size_t new_block_size;
    size_t extend_size;
    char *ptr;
    
    if(heap==NULL){
		mm_init();
		}
    if(size==0){
		return NULL;
		}
	
    size=ALIGN(size+2*WORD_SIZE);
    new_block_size = MAX(size, MINBLOCKSIZE);
    
    ptr=find_fit(new_block_size);
	
    if(ptr!=NULL){
        if (DEBUG)
            printf("FOUND FIT\n");
		place(ptr,new_block_size);
        return ptr;
    }else{
        if (DEBUG)
            printf("NO FIT FOUND\n");
		ptr=extend_heap(new_block_size/WORD_SIZE);
		if(ptr!=NULL){
				place(ptr,new_block_size);
				return ptr;
        }else{
            return NULL;
        }
    }
}
/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *block)
{
    if (block == (void*)-1) 
    {
        return;
    }
    size_t block_size = GET_SIZE(block);
if (heap == 0){
        mm_init();
    }
    WRITE(HDR(block), PACK(block_size, 0));
    WRITE(FTR(block), PACK(block_size, 0));
    coalesce(block);
}

static void* coalesce(void* block){
    if (DEBUG)
        printf("STARTING COALESCING");    
    size_t new_size=GET_SIZE(block);
    if (!(GET_ALLOCATED(PREV_BLOCK(block)))){ // Coalesce before : if a free block is found, we change its size field
        if (DEBUG)
            printf("COALESCING BEFORE");
        if (!GET_ALLOCATED(NEXT_BLOCK(block))){ // Coalesce after : if a free block is found, we remove it from the free_list and merge 'downwards'
            if (DEBUG)
                printf(" AND AFTER");
            remove_free_block(NEXT_BLOCK(block));
            new_size+=GET_SIZE(NEXT_BLOCK(block))+2*WORD_SIZE; // we gain space corresponding to a pair header-footer
        }
        block=PREV_BLOCK(block);
        new_size+=GET_SIZE(block)+2*WORD_SIZE;
    }else{
        if (!GET_ALLOCATED(NEXT_BLOCK(block))){ // If the block before is not free but the one after is
            if (DEBUG)
                printf("COALESCING AFTER ONLY");
            new_size+=GET_SIZE(NEXT_BLOCK(block)) + 2*WORD_SIZE;
            if (NEXTFREE(NEXT_BLOCK(block)) != (void*)-1)
            {
                WRITE(NEXTFREE(NEXT_BLOCK(block))+WORD_SIZE, block);
            }
            if (PREVFREE(NEXT_BLOCK(block)) != (void*)-1){
                WRITE(PREVFREE(NEXT_BLOCK(block)), block);
            }else{
                free_list=block;
                if (DEBUG)
                    printf("Current free list first block : %p\n", free_list);
            }
            WRITE(block, NEXTFREE(NEXT_BLOCK(block)));
            WRITE(block+WORD_SIZE, PREVFREE(NEXT_BLOCK(block)));
        } else { // Else we add an entry to the list
            if (DEBUG)
                printf("NO COALESCING POSSIBLE\n");
            WRITE(block,free_list);
            WRITE(block+WORD_SIZE, -1);
            free_list=block;
            if (NEXTFREE(block)!=(void*)-1){
                WRITE(NEXTFREE(block)+WORD_SIZE, block);
            }
            if (DEBUG)
                printf("Current free list first block : %p\n", free_list);
        }
    }
    WRITE(HDR(block), PACK(new_size,0)); //Finally, we write the proper size in the newly created free block
    WRITE(FTR(block), PACK(new_size,0)); //Finally, we write the proper size in the newly created free block
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void* new_ptr;
    int i=0;
    size_t old_size=GET_SIZE(ptr);
    if (ptr==NULL){
        return mm_malloc(size);
    }
    if (size==0){
        mm_free(ptr);
        return NULL;
    }
    size_t new_size=ALIGN(size+2*WORD_SIZE);
    if (new_size<=old_size){
        printf("Skipping\n");
        if (old_size-new_size >= MINBLOCKSIZE){
            printf("Splitting\n");
            WRITE(HDR(ptr), PACK(size,1));
            WRITE(FTR(ptr), PACK(size,1));
            WRITE(free_list+WORD_SIZE,ptr);
            WRITE(NEXT_BLOCK(ptr), free_list);
            WRITE(NEXT_BLOCK(ptr)+WORD_SIZE, (void*) -1);
            WRITE(HDR(NEXT_BLOCK(ptr)), PACK(old_size-new_size-2*WORD_SIZE,0));
            WRITE(FTR(NEXT_BLOCK(ptr)), PACK(old_size-new_size-2*WORD_SIZE,0));
        }
        return ptr;
    }else{
        printf("Not skipping\n");
        new_ptr=mm_malloc(size);
        size_t cpy_size= MIN(size,old_size);
        for (i=0;i<cpy_size;i++){
            *((unsigned char*) new_ptr+i)= *((unsigned char*)ptr+i);
        }
        mm_free(ptr);
        return new_ptr;
    }
    return NULL;
}



static void *find_fit(size_t size){
	void *ptr;
	if (DEBUG)
        printf("Find Fit Start\n");
	for (ptr = free_list; ptr!=(void*)-1; ptr = NEXTFREE(ptr)){
		if (DEBUG)
            printf("Proposed size : %ld, Wanted size : %ld\n", (size_t) GET_SIZE(ptr),size);
        if (size<=GET_SIZE(ptr)){
			return ptr;
		}
	}

	return NULL;
}

static void place(void *block, size_t asize){
	
	if (DEBUG)
        printf("Place Start");
    if (DEBUG)
        printf("HDR IS: %x\n",HDR(block));
	
	size_t free_size = GET_SIZE(block);
    remove_free_block(block);   
    if ((free_size - asize) >= MINBLOCKSIZE) {
        if (DEBUG)
        	printf("In If\n");
	    //If the difference between free size and allocated size is larger than minimal block size, divide it into two blocks and coallesce the remaining
        WRITE(HDR(block), PACK(asize, 1));
        WRITE(FTR(block), PACK(asize,1));
		
        block = NEXT_BLOCK(block);
        WRITE(HDR(block), PACK((free_size-asize-2*WORD_SIZE), 0));
        WRITE(FTR(block), PACK((free_size-asize-2*WORD_SIZE), 0));
        WRITE(block, free_list);
        WRITE(block+WORD_SIZE, (void*)-1);
        if (free_list!=(void*)-1){
            WRITE(free_list+WORD_SIZE, block);
        }else{
            free_list=block;
        }
        block=PREV_BLOCK(block);
    } else { 
        if (DEBUG)
    		printf("In Else\n");
        remove_free_block(block);
        WRITE(HDR(block), PACK(free_size, 1));
        WRITE(FTR(block), PACK(free_size, 1));
    }
}

static void *extend_heap(size_t words){
    void *block=NULL;
    size_t asize;

    if(words%2!=0){
        asize = (words+1)*WORD_SIZE;
    }
    else{
        asize = words*WORD_SIZE;
    }

    if (asize < CHUNK_SIZE)
        asize = CHUNK_SIZE;

    // Try to grow heap by given size 
    if ((block = mem_sbrk(asize+2*WORD_SIZE)) == (void *)-1)
        return NULL;

    // block points to the first data byte of the new free block to be declared
    WRITE(HDR(block), PACK(asize, 0)); // declare a new free block, add to free_list
    WRITE(block,free_list);
    WRITE(block+WORD_SIZE, (void*)-1);
    if (free_list!=(void*)-1)
        WRITE(free_list+WORD_SIZE, block);
    free_list=block;
    WRITE(FTR(block), PACK(asize, 0));
    WRITE(HDR(NEXT_BLOCK(block)), PACK(0, 1)); // epilogue
    return block;
}

static void remove_free_block(void *block){
    if (DEBUG)
    	printf("Remove Free Block Check Start\n");
	//printf("Block is %s\n",block);
	
    // We use here that "block" points to the block.next field, and block.prev is in block+WORD_SIZE
    //printf("Inside if");
    if (PREVFREE(block)!= (void*)-1){
        if (DEBUG)  
            printf("Previous free block : %p, next free block : %p\n", PREVFREE(block), NEXTFREE(block));
        WRITE(PREVFREE(block), NEXTFREE(block));
    }else{
        free_list = NEXTFREE(block);
    }
    if(NEXTFREE(block) != (void*)-1){
        if (DEBUG)
            printf("Read value : %p\n",PREVFREE(block));
        WRITE(NEXTFREE(block)+WORD_SIZE, PREVFREE(block));
    }    
}

static void displayBlock(void* block){
    size_t block_size= (IS_BOUND(block)? 0 :GET_SIZE(block));
    int i;
    if (block_size)
        printf("[[ %d | %s ]]", block_size, (GET_ALLOCATED(block) ? "Allocated" : "Free"));
    for (i=0;i<block_size;i++){
        printf("[ %x ]", *((unsigned char*)block+i));
    }
    printf("[[ %d | %s ]]\n", GET_SIZE_HERE(block+block_size), (GET_ALLOCATED_HERE(block+block_size) ? "Allocated" : "Free"));
}

static void displayHeap(int verbose){
    void* cursor=mem_heap_lo();
    int i=0;
    if (verbose)
        printf(    "--------------------- Prologue ---------------------\n");
    displayBlock(cursor);
    cursor+=2*WORD_SIZE;
    do{
        if (verbose)
            printf("--------------------- Block %d ---------------------\n", i);
        if (verbose)
            printf("Block address : %p, Header address : %p, Footer address : %p\n", cursor, HDR(cursor), FTR(cursor));
        displayBlock(cursor);
        cursor=NEXT_BLOCK(cursor);
        i++;
    }while(cursor<mem_heap_hi());
    if (verbose)
        printf(    "--------------------- Epilogue ---------------------\n");
    cursor-=WORD_SIZE;
    displayBlock(cursor);
    if (verbose)
        printf(    "----------------------------------------------------\n");
}

static int checkBlock(void * block){
    // Check header & footer
    if (READ(HDR(block))!=READ(FTR(block))){
        printf("Header and footer are not identical.\n");
        //printf("%x || %x", READ(HDR(block)), READ(FTR(block)));
        return -1;
    }
    if (GET_SIZE(block)%8!=0){
        // We use the fact that header+footer is two words, so 8 bytes, hence keeps alignment
        printf("Size of block is not multiple of alignment.\n");
        return -1;
    }
    if (!IS_BOUND(block) && !GET_ALLOCATED(block) && !checkFreeInFreeList(block)){
        printf("Non-allocated block not found in list of free blocks\n");
        return -1;
    }
    // Other tests
    printf("Block ok\n");
    return 1;
}

static int checkFreeList(){
    void* cursor=free_list;
    int ok=1;
    int i=0;
    int max_free_list_size = ((int) mem_heap_hi()- (int) mem_heap_lo())/4*WORD_SIZE;
    ok = ok && ((cursor == (void*) -1) ||(PREVFREE(cursor)==(void*)-1) && (GET_ALLOCATED(cursor)==0));
    printf("--------------------- Checking free list ---------------------\n");
    printf("Address of first free block : %p\n", free_list);
    while (i<max_free_list_size && cursor!=(void*)-1){
        printf("Address of free block : %p\n", cursor);
        //displayBlock(cursor);
        if (GET_ALLOCATED(cursor)==0){
            printf("Free block ok\n");
        }else{
            printf("Free block is not really free");
        }
        ok = ok && (GET_ALLOCATED(cursor)==0);
        cursor=NEXTFREE(cursor);
        i++;
    }
    if (cursor!=(void*)-1){
        ok=0;
        printf("Loop or missing a free list terminator\n");
    }
    printf("---------------------- Free list %sOK----------------------\n", ok ? "":"NOT ");
}

static int checkFreeInFreeList(void* block){
    void* cursor=free_list;
    int i=0;
    int max_free_list_size = ((int) mem_heap_hi()- (int) mem_heap_lo())/4*WORD_SIZE;
    while (i<max_free_list_size && cursor!=(void*)-1){
        if (block==cursor){
            return 1;
        }
        cursor=NEXTFREE(cursor);
        i++;
    }
    return 0;
}

static int checkHeap(){
    int heap_ok=1;
    void* block=mem_heap_lo();
    printf("--------------------- Checking heap ---------------------\n");
    printf("Heap address : %p\n", block);
    while (!IS_EPILOGUE(block)){
        displayBlock(block);
        heap_ok = heap_ok && (checkBlock(block)==1);
        block = NEXT_BLOCK(block);
    }
    block-=WORD_SIZE;
    //displayBlock(block);
    heap_ok = heap_ok && (checkBlock(block)==1);
    printf("---------------------- Heap %sOK----------------------\n", heap_ok ? "":"NOT ");
    return heap_ok;
}

int mm_checkAll(){
    displayHeap(1);
    return checkFreeList() && checkHeap();
}