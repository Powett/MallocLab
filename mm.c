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

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define WORD_SIZE 4
#define POINTER_SIZE 4

#define CHUNK_SIZE 200*ALIGNMENT

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define READ(p)  (*(unsigned int*)(p)) 
#define WRITE(p,x)  (*(unsigned int*)(p)=(x))

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

/* Header shape :  */
/* Footer shape : [(unsigned int) size] */
#define HEADER_SIZE WORD_SIZE+2*POINTER_SIZE // WARNING : This size corresponds to a FREE BLOCK (the 2 pointers are erased in an allocated block)
#define FOOTER_SIZE WORD_SIZE

#define MAX(x, y) ((x) > (y)? (x) : (y))

#define HDR(block)  ( (void*) block - HEADER_SIZE)  //Returns address of the header of a given block
#define PACK(size,is_allocated) (size | is_allocated) // Sizes are a multiple of Alignment (8) : we can use the parity bit to store the is_allocated boolean 
#define GET_SIZE(block) ( READ(HDR(block)) & ~0x7)
#define GET_ALLOCATED(block) ( READ(HDR(block)) & 0x1)
#define FTR(block)  ( (void*) (block) + GET_SIZE(HDR(block)))  //Returns address of the footer of a given block

#define NEXT_BLOCK(block) (FTR(block)+WORD_SIZE)
#define PREV_BLOCK(block) ((void *)(block) - GET_SIZE(HDR(block) - WORD_SIZE))

#define NEXTFREE(block) (*(void **) block) // Address of the next free block (beginning of block = next.next)
#define PREVFREE(block) (*(void **) (block+WORD_SIZE)) // Address of the prev free block (beginning of block = prev.next)

// Private variables represeneting the heap and free list within the heap
static char *heap = 0;  /* Points to the start of the heap */
static char *free_list = 0;  /* Points to the frist free block */


static void *extend_heap(size_t words);
static void place(void *block, size_t asize);
static void *find_fit(size_t size);
static void *coalesce(void *block);
static int checkBlock(void * block);
static void displayBlock(void* block);
static int checkHeap();


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap = mem_sbrk(2*WORD_SIZE + HEADER_SIZE+FOOTER_SIZE+CHUNK_SIZE/WORD_SIZE)) == (void *)-1) // +2 due to prologue and epilogue header/footer
    {
        return -1;
    }
    WRITE(heap,PACK(0,1)); // Prologue header
    heap+=WORD_SIZE;
    WRITE(heap,PACK(CHUNK_SIZE/WORD_SIZE,0)); // Size and is_allocated
    heap+=WORD_SIZE;
    WRITE(heap+WORD_SIZE,-1); // No prev
    WRITE(heap+WORD_SIZE+POINTER_SIZE,-1); // No next
    WRITE(FTR(heap+WORD_SIZE),PACK(CHUNK_SIZE/WORD_SIZE,0)); // Size and is_allocated
    WRITE(FTR(heap+WORD_SIZE)+WORD_SIZE,PACK(0,1)); // Epilogue header
    free_list=heap;
    displayBlock(heap);
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    int newsize = ALIGN(size + SIZE_T_SIZE);
    void *p = mem_sbrk(newsize);
    if (p == (void *)-1)
	return NULL;
    else {
        *(size_t *)p = size;
        return (void *)((char *)p + SIZE_T_SIZE);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *block)
{
    if (block == 0) 
    {
        return;
    }
    size_t block_size = GET_SIZE(HDR(block));
    if (heap == 0){
        mm_init();
    }

    WRITE(HDR(block), PACK(block_size, 0));
    WRITE(FTR(block), PACK(block_size, 0));
    coalesce(block);
}

static void* coalesce(void* block){

    // REDO : ONLY ONE COALESCING UP AND DOWN POSSIBLE
    size_t new_size=GET_SIZE(block);
    

    if (!GET_ALLOCATED(NEXT_BLOCK(block))){ // Coalesce after : if a free block is found, we remove it from the free_list and merge 'downwards'
        new_size+=GET_SIZE(NEXT_BLOCK(block));
        if (NEXT_BLOCK(block) != (void*)-1)
        {
            WRITE(NEXTFREE(NEXT_BLOCK(block))+WORD_SIZE, NEXT_BLOCK(block)+WORD_SIZE);
        }
        if (NEXT_BLOCK(block)+WORD_SIZE != (void*)-1){
            WRITE(PREVFREE(NEXT_BLOCK(block)), NEXT_BLOCK(block));
        }
        
        
    }
    
    if (!(GET_ALLOCATED(PREV_BLOCK(block)))){ // Coalesce before : if a free block is found, we change its size field
        block=PREV_BLOCK(block);
        new_size+=GET_SIZE(block);
    } else { // If not, we have to create a new entry in free_list
        WRITE(block,free_list);
        WRITE(free_list+WORD_SIZE,block);
        WRITE(block+WORD_SIZE, -1);
    }
    WRITE(HDR(block), PACK(new_size,0));
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}

static void displayBlock(void* block){
    size_t block_size=GET_SIZE(HDR(block));
    int i;
    printf("[[ %d | %s ]]", block_size, (GET_ALLOCATED(HDR(block)) ? "Allocated" : "Free"));
    for (i=0;i<block_size;i++){
        printf("[ %x ]", *(unsigned int *)(block+i));
    }
    printf("[[ %d | %s ]]", block_size, (GET_ALLOCATED(FTR(block)) ? "Allocated" : "Free"));
}

static int checkBlock(void * block){
    // Check header & footer
    if (HDR(block)!=FTR(block)){
        printf("Header and footer are not identical.\n");
        return -1;
    }
    if (GET_SIZE(block)%8!=0){
        // We use the fact that header+footer is two words, so 8 bytes, hence keeps alignment
        printf("Size of block is not multiple of alignment.\n");
        return -1;
    }
    // Other tests
    return 1;
}

static int checkHeap(){
    int heap_ok=1;
    void* block;
    printf("Heap address : %p\n", block);
    while (GET_SIZE(HDR(block)) > 0){
        printblock(block);
        heap_ok = heap_ok && (checkblock(block)==1);
        block = NEXT_BLOCK(block);
    }
    return heap_ok;
}