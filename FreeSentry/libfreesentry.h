// LGPL 2.1 license
// Copyright 2007-2010 Yves Younan
// This code is based on some of the code used in PAriCheck

// Copyright 2015 Cisco Systems

/*
This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
*/

#ifndef LIBUAF_H
#define LIBUAF_H

#define HASHSIZE (1048576*64)
#define HASHSIZE2 (1048576)
#define BPTRSIZE 4
#define BITSHIFT 5
// 1 << BITSHIFT
#define BITSHIFTVAL 32

#define KERNELMEM 0xC0000000
// kernelmem - 16MB
#define STACKTOPMEM 0xBF000000
#define PAGESIZE 4096
// page size (4096 = 2^12) 
#define PAGESHIFT 12
#define CHARSIZE 8
// char size (log2(8)=3)
#define PAGESHIFTBIT (PAGESHIFT+3)
#define PAGETABLESIZE (KERNELMEM>>PAGESHIFTBIT)

// must be a multiple of pagesize
#define PTRINFOELS 81920
#define PTRINFOMAP (PTRINFOELS*(sizeof(struct hashelement)))

//#define LABELTYPE unsigned short
#define LABELTYPE unsigned int
#define INTSIZE (sizeof(LABELTYPE))
#define LABELSIZESHIFT 1
#define STACKMAXSIZE (8192 * 1024)
#define MAXMEM (KERNELMEM>>BITSHIFT)
#define HASHTBSZ (MAXMEM * INTSIZE)

#ifdef DEBUG
#define DEBUG_PRINT(lvl, buf, nl) debugprint(lvl, buf,nl)
#define DEBUG_PRINT_NR(lvl, nr, nl) debugprintnr(lvl, nr,10,nl)
#define DEBUG_PRINT_PTR(lvl, nr, nl) debugprintnr(lvl, (unsigned int) nr,16,nl)
#define DEBUG_PRINT_NR_BASE(lvl, nr, base, nl) debugprintnr(lvl, nr,base,nl)
#else
#define DEBUG_PRINT(lvl, buf, nl) do{ } while ( 0 )
#define DEBUG_PRINT_NR(lvl, nr, nl) do{ } while ( 0 )
#define DEBUG_PRINT_PTR(lvl, nr, nl) do{ } while ( 0 )
#define DEBUG_PRINT_NR_BASE(lvl, nr, base, nl) do{ } while ( 0 )
#endif

/*
# define YY_SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))
typedef struct
  {
    unsigned long int __val[YY_SIGSET_NWORDS];
  } __sigset_t;

*/
typedef int __jmp_buf[6];

struct __jmp_buf_tag
  {
    /* NOTE: The machine-dependent definitions of `__sigsetjmp'
       assume that a `jmp_buf' begins with a `__jmp_buf' and that
       `__mask_was_saved' follows it.  Do not move these members
       or add others before it.  */
    __jmp_buf __jmpbuf;         /* Calling environment.  */
    int __mask_was_saved;       /* Saved the signal mask?  */
    __sigset_t __saved_mask;    /* Saved signal mask.  */
  };

typedef struct __jmp_buf_tag jmp_buf[1];


/*
struct backptrs {
    unsigned int size;
    unsigned int curr;
    unsigned int bptr[];
};*/

struct hashelement {
    struct hashelement *next;
    struct hashelement *ptrnext;
    struct hashelement *prev;
    struct hashelement *ptrprev;
//    char *obj;
    LABELTYPE objlbl;
    void *bptr;
};

static void * (*origmmap) (void *, size_t, int, int, int, off_t);
static int (*origmunmap) (void *, size_t);
//static int (*origbrk)(void *);
//static void * (*origsbrk)(intptr_t);
static void (*origlongjmp)(jmp_buf, int);

int sysmunmap(void *, size_t);
void *sysmmap(void *, size_t, int, int, int, off_t);


void yyinit();
void registerptr (char **);
void registerptrobj (char **, char *);
void unregisterptrs(char *, unsigned int);
void unregisterstackptrs();
void labelspace(void *, unsigned int, LABELTYPE);
void freelabelspace(void *, unsigned int);

struct malloc_chunk {
        size_t               prev_foot;  /* Size of previous chunk (if free).  */
        size_t               head;       /* Size and inuse bits. */
        struct malloc_chunk* fd;         /* double links -- used only if free. */
        struct malloc_chunk* bk;
};
typedef struct malloc_chunk* mchunkptr;
#define mem2chunk(mem)      ((mchunkptr)((char*)(mem) - 8))
#define SIZE_T_ZERO         ((size_t)0)
#define SIZE_T_ONE          ((size_t)1)
#define SIZE_T_TWO          ((size_t)2)
#define SIZE_T_FOUR         ((size_t)4)
#define PINUSE_BIT          (SIZE_T_ONE)
#define CINUSE_BIT          (SIZE_T_TWO)
#define FLAG4_BIT           (SIZE_T_FOUR)
#define INUSE_BITS          (PINUSE_BIT|CINUSE_BIT)
#define FLAG_BITS           (PINUSE_BIT|CINUSE_BIT|FLAG4_BIT)
#define chunksize(p)        ((p)->head & ~(FLAG_BITS))


#endif
