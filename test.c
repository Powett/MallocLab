/*
 * mdriver.c - CS:APP Malloc Lab Driver
 * 
 * Uses a collection of trace files to tests a malloc/free/realloc
 * implementation in mm.c.
 *
 * Copyright (c) 2002, R. Bryant and D. O'Hallaron, All rights reserved.
 * May not be used, modified, or copied without permission.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <float.h>
#include <time.h>

#include "mm.h"
#include "memlib.h"
#include "fsecs.h"
#include "config.h"

int main(char argc, char* argv[]){
    mem_init();
    mem_reset_brk();
    mm_init();
    //void* ptr=mm_malloc(2);
    void* ptr2=mm_malloc(1);
    mm_free(ptr2);
    //mm_checkAll();
    //void* ptr3=mm_realloc(ptr2,500);
    //void* ptr3=mm_malloc(4);
    //void* ptr4=mm_malloc(5);
    // mm_free(ptr);
    // mm_free(ptr3);
    //mm_free(ptr2);
    // mm_free(ptr4);
    
    
    
    //mm_checkAll();
}