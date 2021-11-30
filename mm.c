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

#define DEBUG 1


/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define WORD_SIZE 4
#define DSIZE 8
#define CHUNK_SIZE 6*ALIGNMENT 
#define MINBLOCKSIZE 16 // min size is HEADER_SIZE + FOOTER_SIZE + 2*WORD_SIZE = 4*WORD_SIZE(we have to keep some space for next & prev pointers)
/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define READ(p)  (*(unsigned int*)(p)) 
#define WRITE(p, x)   (*(size_t *)(p) = (x))

#define HEADER_SIZE WORD_SIZE // WARNING : This size corresponds to a ALLOCATED BLOCK
#define FOOTER_SIZE WORD_SIZE

#define MAX(x, y) ((x) > (y)? (x) : (y))
#define MIN(x, y) ((x) > (y)? (y) : (x))

#define HDR(block)     ((void *)(block) - WORD_SIZE)
#define PACK(size,is_allocated) ((size) | (is_allocated)) // Sizes are a multiple of Alignment (8) : we can use the parity bit to store the is_allocated boolean 
#define GET(p)        (*(size_t *)(p))
#define GET_SIZE(p) (GET(p) & ~0x1)
#define GET_ALLOCATED(p) (GET(p) & 0x1)
#define GET_SIZE_HERE(p) ( READ(p) & ~0x7)
#define GET_ALLOCATED_HERE(p) ( READ(p) & 0x1)
#define FTR(block)     ((void *)(block) + GET_SIZE(HDR(block)) - DSIZE)


#define NEXT_BLOCK(block) ((void *)(block) + GET_SIZE(HDR(block)))
#define PREV_BLOCK(block) ((void *)(block) - GET_SIZE(HDR(block) - WORD_SIZE))

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
static char *free_list = 0;  /* Points to the first free block */


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


//mm_init - Initialize the malloc package

int mm_init(void)
{
  if ((heap = mem_sbrk(2*MINBLOCKSIZE)) == (void *)-1)
      return -1; 
  WRITE(heap,             PACK(MINBLOCKSIZE, 1));           // Prologue header 
  WRITE(heap +    WORD_SIZE,  PACK(MINBLOCKSIZE, 0));           // Free block header 

  WRITE(heap + (2*WORD_SIZE), PACK(0,0));                       // Space for next pointer 
  WRITE(heap + (3*WORD_SIZE), PACK(0,0));                       // Space for prev pointer 
  
  WRITE(heap + (4*WORD_SIZE), PACK(MINBLOCKSIZE, 0));           // Free block footer 
  WRITE(heap + (5*WORD_SIZE), PACK(0, 1));                      // Epilogue header 

  free_list = heap + (WORD_SIZE);

  return 0;
}

//mm_malloc - Allocates a block of memory of memory 

void *mm_malloc(size_t size)
{  
  
  if (size == 0)
      return NULL;

  size_t asize;      
  size_t extendsize;  
  char *block;

  asize = MAX(ALIGN(size) + DSIZE, MINBLOCKSIZE);

  if ((block = find_fit(asize))) {
    place(block, asize);
    return block;
  }

  extendsize = MAX(asize, MINBLOCKSIZE);
  if ((block = extend_heap(extendsize/WORD_SIZE)) == NULL)
    return NULL;

  place(block, asize);

  return block;
}

//mm_free - Frees the block pointed to by a pointer

void mm_free(void *block)a 
{ 
   
  if (!block)
      return;

  size_t size = GET_SIZE(HDR(block));

  WRITE(HDR(block), PACK(size, 0));
  WRITE(FTR(block), PACK(size, 0));

  coalesce(block);
}

//mm_realloc - Simple implementation in terms of mm_malloc and mm_free

void *mm_realloc(void *ptr, size_t size)
{
  if (ptr == NULL)
    return mm_malloc(size);

  if (size == 0) {
    mm_free(ptr);
    return NULL;
  }

  size_t asize = MAX(ALIGN(size) + DSIZE, MINBLOCKSIZE);
  size_t current_size = GET_SIZE(HDR(ptr));

  void *block;
  char *next = HDR(NEXT_BLOCK(ptr));
  size_t newsize = current_size + GET_SIZE(next);

  if (asize == current_size)
    return ptr;

  if ( asize <= current_size ) {

    if( asize > MINBLOCKSIZE && (current_size - asize) > MINBLOCKSIZE) {  

      WRITE(HDR(ptr), PACK(asize, 1));
      WRITE(FTR(ptr), PACK(asize, 1));
      block = NEXT_BLOCK(ptr);
      WRITE(HDR(block), PACK(current_size - asize, 1));
      WRITE(FTR(block), PACK(current_size - asize, 1));
      mm_free(block);
      return ptr;
    }

    block = mm_malloc(asize);
    memcpy(block, ptr, asize);
    mm_free(ptr);
    return block;
  }

  else {

    if ( !GET_ALLOCATED(next) && newsize >= asize ) {

      remove_free_block(NEXT_BLOCK(ptr));
      WRITE(HDR(ptr), PACK(asize, 1));
      WRITE(FTR(ptr), PACK(asize, 1));
      block = NEXT_BLOCK(ptr);
      WRITE(HDR(block), PACK(newsize-asize, 1));
      WRITE(FTR(block), PACK(newsize-asize, 1));
      mm_free(block);
      return ptr;
    }  
    
    block = mm_malloc(asize); 
    memcpy(block, ptr, current_size);
    mm_free(ptr);
    return block;
  }

}

//extend_heap - Extends the heap rounding off the size to nearest block size

static void *extend_heap(size_t words)
{
  char *block;
  size_t asize;

  asize = (words % 2) ? (words + 1) * WORD_SIZE : words * WORD_SIZE;
  if (asize < MINBLOCKSIZE)
    asize = MINBLOCKSIZE;
  
  // Grow the heap by the asize 
  if ((block = mem_sbrk(asize)) == (void *)-1)
    return NULL;

  WRITE(HDR(block), PACK(asize, 0));
  WRITE(FTR(block), PACK(asize, 0));
  WRITE(HDR(NEXT_BLOCK(block)), PACK(0, 1)); /* Move the epilogue to the end */
 
  return coalesce(block); 
}

//find_fit - find free block using first fit method

static void *find_fit(size_t size)
{
  // First-fit search 
  void *block;

  for (block = free_list; GET_ALLOCATED(HDR(block)) == 0; block = NEXTFREE(block)) {
    if (size <= GET_SIZE(HDR(block))) 
      return block; 
  }
  return NULL; 
}

//remove_free_block - Removes the given free block pointed to by block from the free list
static void remove_free_block(void *block)
{
  if(block) {
    if (PREVFREE(block))
      NEXTFREE(PREVFREE(block)) = NEXTFREE(block);
    else
      free_list = NEXTFREE(block);
    if(NEXTFREE(block) != NULL)
      PREVFREE(NEXTFREE(block)) = PREVFREE(block);
  }
}

//coalesce - Coalesce memory using boundary tag method

static void *coalesce(void *block)
{
  size_t prev_alloc = GET_ALLOCATED(FTR(PREV_BLOCK(block))) || PREV_BLOCK(block) == block;
  size_t next_alloc = GET_ALLOCATED(HDR(NEXT_BLOCK(block)));

  // Get the size of the current free block
  size_t size = GET_SIZE(HDR(block));

  if (prev_alloc && !next_alloc) {
    size += GET_SIZE(HDR(NEXT_BLOCK(block)));  
    remove_free_block(NEXT_BLOCK(block));
    WRITE(HDR(block), PACK(size, 0));
    WRITE(FTR(block), PACK(size, 0));
  }
  else if (!prev_alloc && next_alloc) {
    size += GET_SIZE(HDR(PREV_BLOCK(block)));
    block = PREV_BLOCK(block); 
    remove_free_block(block);
    WRITE(HDR(block), PACK(size, 0));
    WRITE(FTR(block), PACK(size, 0));
  } 

  else if (!prev_alloc && !next_alloc) {
    size += GET_SIZE(HDR(PREV_BLOCK(block))) + 
            GET_SIZE(HDR(NEXT_BLOCK(block)));
    remove_free_block(PREV_BLOCK(block));
    remove_free_block(NEXT_BLOCK(block));
    block = PREV_BLOCK(block);
    WRITE(HDR(block), PACK(size, 0));
    WRITE(FTR(block), PACK(size, 0));
  }

  NEXTFREE(block) = free_list;
  PREVFREE(free_list) = block;
  PREVFREE(block) = NULL;
  free_list = block;
 
  return block;
}

//place - Places a block of the given size in the free block pointed to by the given pointer 'block'
static void place(void *block, size_t asize)
{  
  // Size of free block 
  size_t fsize = GET_SIZE(HDR(block));

  if((fsize - asize) >= (MINBLOCKSIZE)) {
    WRITE(HDR(block), PACK(asize, 1));
    WRITE(FTR(block), PACK(asize, 1));
    remove_free_block(block);
    block = NEXT_BLOCK(block);
    WRITE(HDR(block), PACK(fsize-asize, 0));
    WRITE(FTR(block), PACK(fsize-asize, 0));
    coalesce(block);
  }
  else {
    WRITE(HDR(block), PACK(fsize, 1));
    WRITE(FTR(block), PACK(fsize, 1));
    remove_free_block(block);
  }
}

static void displayBlock(void* block){
    size_t block_size= (IS_BOUND(block)? 0 :GET_SIZE(block));
    int i;
    if (block_size)
        printf("[[ %d | %s ]]", block_size, (GET_ALLOCATED(block) ? "Allocated" : "Free"));
		
    for (i=0;i<block_size;i++){
        printf("[ %x ]", *((unsigned char*)block+i));
		printf("Block size: %d",block_size);
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
	printf("Displaying Heap\n");
    displayHeap(1);
	printf("Displaying Heap DONE\n");
    return checkFreeList() && checkHeap();
}