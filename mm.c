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

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define READ(p)  (*(unsigned int*)(p)) 
#define WRITE(p,x)  (*(unsigned int*)(p)=(x))

/*
 * Layout of a free block, size N=k*ALIGNMENT 
 *  
 *  [HEADER][ char[N-2] ][FOOTER]
 * Where :
 *  [HEADER] = [ PACK( (unsigned int)N , (bit) allocated) ) ] [ (unsigned int*) prev ] [ (unsigned int*) next]
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

#define HDR(block)  ( (char*) block - HEADER_SIZE)  //Returns address of the header of a given block
#define PACK(size,is_allocated) (size | is_allocated) // Sizes are a multiple of Alignment (8) : we can use the parity bit to store the is_allocated boolean 
#define GET_SIZE(block) ( GET(HDR(block)) & ~0x7)
#define GET_ALLOCATED(block) ( GET(HDR(block)) & 0x1)
#define FTR(block)  ( (char*) block + GET_SIZE(HDR(block)))  //Returns address of the footer of a given block

static char* heap;  // Pointer to heap 

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap = mem_sbrk(HEADER_SIZE+FOOTER_SIZE) == (void *)-1) // We use the fact that here, header + footer size is multiple of aligment(no padding needed)
        return -1;
    WRITE(heap,PACK(0,0)); // Size and is_allocated
    WRITE(heap+WORD_SIZE,-1); // No prev
    WRITE(heap+WORD_SIZE+POINTER_SIZE,-1); // No next
    WRITE(heap+WORD_SIZE+2*POINTER_SIZE,PACK(0,0)); // Size and is_allocated
    
    //call extend_heap function
    
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
void mm_free(void *ptr)
{
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

int mm_check(){
    
}














