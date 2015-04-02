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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
//#define __USE_GNU
#include <dlfcn.h>
#include <sys/mman.h>

#include "libfreesentry.h"
#include <stdint.h>
#include <signal.h>

#include <assert.h>

#include <unistd.h>

#include <sys/syscall.h>

#include <signal.h>

//#include <setjmp.h>

//#define DEBUG
#define DEBUGLEVEL 1

// turn off stack protection
#define NOSTACK
// turn on optimization for global variables
//#define GLOBALOPT
// turn on stats
//#define STATS
//#define DEBUGCHK
#define OOBSUPPORT 8

unsigned int currlabel = 1;

struct hashelement **yyhash = 0;
struct hashelement **yyhashptr = 0;
struct hashelement **yylabelobj = 0;
char *yypages = 0;

struct hashelement *yyptrinfomap = 0;
struct hashelement *yyptrinfoend = 0;
struct hashelement *yyfreelist = 0;


char munmapcalled = 0;

struct hashelement *yycache = 0;

char *invalidmem = (char *) KERNELMEM;

LABELTYPE *labelhash = 0;

#ifdef GLOBALOPT
#define globalmembegin 0x8048000
char *globalmemend = 0;
#endif


#ifdef STATS
uint64_t total = 0;
#endif

#define CATCHERRORS
#ifdef CATCHERRORS

void segfault_sigaction(int signal, siginfo_t *si, void *arg)
{
    unsigned int addr = (unsigned int) si->si_addr;
    if (addr >= 0xC000000) {
	    printf("\n\n\n\nFreeSentry error: object at location 0x%x or 0x%x or 0x%x was accessed after it was freed\n\n\n\n", addr&0x7FFFFFFF, addr&0x3FFFFFFF, addr&0xBFFFFFFF);
    	    exit(0);
    } else {
	    printf("error: 0x%x\n", addr);
	    abort();
    }
}



#endif

#ifndef DEBUG
#define DEBUGLEVEL 200000
#endif

#ifndef DEBUGLEVEL
#define DEBUGLEVEL 1000
#endif

#ifdef DEBUG

// turn off here and then turn this on in gdb to turn printing of debuging info at runtime
// useful to debug crashes where you don't want thousands and thousands of messages
//static int yy_rtdebug = 0;
static int yy_rtdebug = 1;

static void inline debugprintsz(int level, char *buf, int size, char nl) {
   if (!yy_rtdebug || level < DEBUGLEVEL) return;
   write(2, buf, size);
   if (nl) {
	write(2, "\n", 1);
   }

}

static void debugprint(int level, char *buf,char nl) {
   debugprintsz(level, buf, strlen(buf), nl);
}


static int convint(char *conv, unsigned int size, unsigned int nr, unsigned int base) {
   int i;
   int tmp;
   i = size-1;
   do {
        tmp = nr % base;
        if (tmp<10)
           tmp = tmp+'0';
        else
           tmp = tmp - 10 + 'A';
        conv[i--] = tmp;
   } while ((nr = nr / base) && (i>0));

   return i;
}


static void debugprintnr(int level, unsigned int nr, unsigned int base, char nl) {
   int index;
   char conv[12];
   // checked later too, but this speeds up the whole exercise
   if (!yy_rtdebug || level < DEBUGLEVEL) return;

   index=convint(conv, 12,  nr, base);
   debugprintsz(level, &conv[index+1], 11-index, nl);
}

#endif


static void printerr(char *printstr, char *errmsg) {
	write(2,"ERROR: ", 7);
	write(2, printstr, strlen(printstr));
	write(2, errmsg, strlen(errmsg));
	write(2, "\n", 1);
}

int yy_sysmunmap(void *addr, size_t length) {
   if (!origmunmap) {
     origmunmap = dlsym(RTLD_NEXT, "munmap");
     if (!origmunmap) {
      printerr("dlsym: ", dlerror());
      exit(-1);
     }
   }
   return origmunmap(addr,length);
}

void *yy_sysmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
   if (!origmmap) {
     origmmap = dlsym(RTLD_NEXT, "mmap");
     if (!origmmap) {
      printerr("dlsym: ", dlerror());
      exit(-1);
     }
   }
   return origmmap(addr,length,prot,flags,fd,offset);
}

void yy_longjmp(jmp_buf, int)  __attribute__((noreturn));
void yy_longjmp(jmp_buf env, int val) {
   if (!origlongjmp) {
     origlongjmp = dlsym(RTLD_NEXT, "longjmp");
     if (!origlongjmp) {
      printerr("dlsym: ", dlerror());
      exit(-1);
     }
   }
   origlongjmp(env, val);
   // make gcc happy
   __builtin_unreachable();
}

struct hashelement *getnewelement() {
	struct hashelement *newel;

	if (yyfreelist) {
		newel = yyfreelist;
		yyfreelist = yyfreelist->next;
		return newel;
	}

	if (yyptrinfomap >= yyptrinfoend) {
#if DEBUGLEVEL <= 160
		DEBUG_PRINT(160, "Ran out of space, allocating new ptrinfomap",1);
#endif
		yyptrinfomap = (struct hashelement *) yy_sysmmap(0, PTRINFOMAP, 0x1 | 0x2, 0x02 |  0x20, -1, 0);
		yyptrinfoend = yyptrinfomap + PTRINFOELS;
	}

	newel = yyptrinfomap;
	yyptrinfomap++;
	return newel;
}

void deleteelement(struct hashelement *el) {
	el->next = yyfreelist;
	yyfreelist = el;
}


void inline yyinit() {
  if (!yyhash) {
	char *allocedtable = 0;
#ifdef CATCHERRORS
 	struct sigaction sa;
#endif

	allocedtable = (char *) yy_sysmmap(0, (HASHSIZE*4)+PAGETABLESIZE+HASHTBSZ+(HASHSIZE*4)+PTRINFOMAP, 0x1 | 0x2, 0x02 |  0x20, -1, 0);
	if (allocedtable == (char *) -1) {
	   printerr("ERROR: ", "couldn't allocate memory for hashtable\n");
	   exit(-1);
	}


	yyhash = yyhashptr = (struct hashelement **) (allocedtable);


	allocedtable += HASHSIZE*4;


	yypages = allocedtable;

	allocedtable += PAGETABLESIZE;

	labelhash = (LABELTYPE *) allocedtable;

	allocedtable += HASHTBSZ;

	yylabelobj = (struct hashelement **) allocedtable;

	allocedtable += HASHSIZE*4;

	yyptrinfomap = (struct hashelement *) allocedtable;
	yyptrinfoend = yyptrinfomap + PTRINFOELS;


#ifdef CATCHERRORS
    	memset(&sa, 0, sizeof(struct sigaction));
    	sigemptyset(&sa.sa_mask);
    	sa.sa_sigaction = segfault_sigaction;
    	sa.sa_flags   = SA_SIGINFO;
    	sigaction(SIGSEGV, &sa, NULL);
#endif

  }
}

#define halign(p) (((unsigned long) p)  >> BITSHIFT)

#define align32(p) (((unsigned long) p) & ~31)

static inline LABELTYPE getlabel(void *mem) {
	unsigned long address;
	address = halign(mem);
#ifdef DEBUGCHK
	if (address >= HASHTBSZ/4) {
	   printerr("GETLABEL", "out of bounds access");
	   abort();
	}
#endif
 	return labelhash[address];
}

void labelspace(void *buf, unsigned int size, LABELTYPE label) {
        unsigned int address;
        unsigned int elements;
        elements = size >> BITSHIFT;
        address = halign(buf);

#ifdef DEBUGCHK
	if (label==0) {
	   printerr("LABELSPACE:", "ran out of labels");
	   abort();
	}
#endif

#if DEBUGLEVEL <= 120
   	DEBUG_PRINT(120,"UAF: LABELSPACE - enter, obj:", 0);
        DEBUG_PRINT_PTR(120,buf, 0);
   	DEBUG_PRINT(120,", size:", 0);
   	DEBUG_PRINT_NR(120,size,0);
   	DEBUG_PRINT(120,", elements:", 0);
   	DEBUG_PRINT_NR(120,elements,0);
   	DEBUG_PRINT(120,", address:", 0);
   	DEBUG_PRINT_NR(120,address,0);
   	DEBUG_PRINT(120,", label:", 0);
   	DEBUG_PRINT_NR(120,label,1);
#endif
         while (elements--) {
#if DEBUGLEVEL <= 120
		 DEBUG_PRINT(120, "Labeling: ",0);
   		 DEBUG_PRINT_NR(120,address,1);
#endif
                 labelhash[address++] = label;
         }
}

void freelabelspace(void *buf, unsigned int size) {
	unsigned long address;
	unsigned int elements;
	elements = size >> (BITSHIFT-LABELSIZESHIFT);
        address = halign(buf);
	memset(&labelhash[address], 0x0, elements);
}

static inline unsigned int pagelive(char **obj) {
  unsigned int index;
  unsigned char bit;
  unsigned char pageinfo;
  index = (((unsigned int) obj) >> PAGESHIFTBIT);
#ifdef DEBUGCHK
   if (index >= PAGETABLESIZE) {
	printerr("PAGELIVE", "out of bounds access");
	abort();
   }
#endif

   pageinfo = yypages[index];
   bit = (((unsigned int) obj) >> PAGESHIFT) & (CHARSIZE-1);
   if (!(pageinfo & (1<<bit)))
		return 1;
  return 0;
}


// these 2 functions can be made faster: if 8 pages
// on the same index are being released/allocated we can just set to
// the whole byte to 0 or 255 instead of seperate bits
// this could even be done as a memset for multiple groups of 8
// needs separate handling of "non-aligned" start and end pages
// for now leave it this way, too few mmap/munmaps to care

static inline void setpagelive(char *page) {
  unsigned int index;
  unsigned char pageinfo;
  unsigned char bit;
  if (!munmapcalled) return;
  index = (((unsigned int) page) >> PAGESHIFTBIT);
#ifdef DEBUGCHK
   if (index >= PAGETABLESIZE) {
	printerr("SETPAGELIVE", "out of bounds access");
	abort();
   }
#endif

   pageinfo = yypages[index];
   bit = (((unsigned int) page) >> PAGESHIFT) & (CHARSIZE-1);
   pageinfo = pageinfo & ~(1<<bit);
   yypages[index] = pageinfo;
}

static inline void setpagedead(char *page) {
  unsigned int index;
  unsigned char bit;
  unsigned char pageinfo;
  index = (((unsigned int) page) >> PAGESHIFTBIT);
#ifdef DEBUGCHK
   if (index >= PAGETABLESIZE) {
	printerr("SETPAGEDEAD", "out of bounds access");
	abort();
   }
#endif

   pageinfo = yypages[index];
   bit = (((unsigned int) page) >> PAGESHIFT) & (CHARSIZE-1);
   pageinfo = pageinfo | (1<<bit);
#if DEBUGLEVEL <= 50
   DEBUG_PRINT(50,"UAF: SETPAGEDEAD page:", 0);
   DEBUG_PRINT_PTR(50,page, 0);
   DEBUG_PRINT(50,", index:", 0);
   DEBUG_PRINT_NR(50,index,0);
   DEBUG_PRINT(50,", pageinfo:", 0);
   DEBUG_PRINT_NR(50,pageinfo,1);
#endif
   yypages[index] = pageinfo;
}



void *__curbrk = 0;

int brk(void *addr) {
   //int ret;
   //unsigned int pages, i, nextpage, length;
    unsigned int i;
    void *newbrk;

   newbrk = (void *) syscall(SYS_brk, addr);

  if (newbrk < addr) {
      __curbrk = newbrk;
      return -1;
  }

  if (!yyhash) {
  	__curbrk = newbrk;
	return 0;
   }

   if (__curbrk > newbrk) {
  	munmapcalled = 1;
      	for (i = (unsigned int) newbrk; i< ((unsigned int) __curbrk); i+=4096) {
        	setpagedead((char *) i);
      	}
   } else {
	if (munmapcalled) {
      	   for (i = (unsigned int) __curbrk; i< ((unsigned int) newbrk); i+=4096) {
        	setpagelive((char *) i);
	   }
	}
   }
   __curbrk = newbrk;
   return 0;
}

void *
sbrk (intptr_t increment)
{
  void *oldbrk;
  if (__curbrk == NULL)
    if (brk (0) < 0)          /* Initialize the break.  */
      return (void *) -1;

  if (increment == 0)
    return __curbrk;

  oldbrk = __curbrk;
  if ((increment > 0
       ? ((uintptr_t) oldbrk + (uintptr_t) increment < (uintptr_t) oldbrk)
       : ((uintptr_t) oldbrk < (uintptr_t) -increment))
      || brk (oldbrk + increment) < 0)
    return (void *) -1;

  return oldbrk;
}


void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
   void *retaddr;
   unsigned int pages, i, nextpage;
   retaddr = yy_sysmmap(addr, length, prot, flags, fd, offset);
   if (yyhash && retaddr != MAP_FAILED) {
      pages = length / PAGESIZE;
      nextpage=0;
      if (munmapcalled) {
      	for (i = 0; i<=pages; i++) {
	   setpagelive(retaddr+nextpage);
	   nextpage+=4096;
        }
      }
   }

   return retaddr;

}


int munmap(void *addr, size_t length) {
   unsigned int pages, i, nextpage;

   if (!yy_sysmunmap(addr, length)) {
	if (!yyhash) return 0;
	pages = length / PAGESIZE;
	nextpage=0;

	munmapcalled=1;
   	for (i = 0; i<=pages; i++) {
	   setpagedead(addr+nextpage);
	   nextpage+=4096;
   	}

	return 0;

   }

   return -1;


}

#ifndef NOSTACK
static unsigned long ptr_demangle(int p) {
        unsigned long ret;
        asm(" movl %1, %%eax;\n"
            " rorl $0x9, %%eax;"
            " xorl %%gs:0x18, %%eax;"
            " movl %%eax, %0;"
        : "=r"(ret)
        : "r"(p)
        : "%eax"
        );
        return ret;
}

void inline int_longjmp (jmp_buf env, int val) {
   unsigned long tmp;
   char *stackend;
   char *stackstart;
   char *stacksaved;

#ifdef DEBUG
   write(2, "longjmp\n", 9);
#endif

   stacksaved = (char *) ptr_demangle(env->__jmpbuf[4]);
   asm("\t movl %%ebp,%0" : "=r"(tmp));
   stackend = ((char *) *((unsigned long *)tmp)) + 8;
   stackstart = ((char *) (tmp)) + 8;

// walk each stack frame by walking EBP
// as long as EBP < saved_SP in jump buf
// we continue freeing

   while (stackend && stackend < stacksaved) {
   	unregisterptrs((char *) stackstart, ((char *)stackend) - ((char *) stackstart));
	tmp = stackend;
   	stackend = ((char *) *((unsigned long *)tmp)) + 8;
   	stackstart = ((char *) (tmp)) + 8;

   }

   yy_longjmp(env, val);

}

void longjmp (jmp_buf env, int val) {
	int_longjmp(env, val);
}

void __longjmp_chk(jmp_buf env, int val) {
	int_longjmp(env, val);
}
#endif

void*  dlmalloc(size_t);
void*  dlcalloc(size_t, size_t);
void   dlfree(void *);
void*  dlrealloc(void *, size_t);

#define sysmalloc dlmalloc
#define syscalloc dlcalloc
#define sysrealloc dlrealloc
#define sysfree dlfree

void *malloc(size_t size) {
	size_t newsize;
        void *p;
        mchunkptr myp;
	unsigned int diff;

	if (!yyhash) yyinit();
#if DEBUGLEVEL <= 120
   	DEBUG_PRINT(120,"UAF: malloc - enter ", 0);
        DEBUG_PRINT_NR(120,size, 1);
#endif

        newsize=size;
#ifdef OOBSUPPORT
	newsize += OOBSUPPORT;
#endif

//	newsize=size;
        p = (void *) sysmalloc(newsize);

        if (p) {
                myp = mem2chunk(p);
                newsize = chunksize(myp) ;

                labelspace(p, newsize, currlabel);
                currlabel++;
#if DEBUGLEVEL <= 120
   		DEBUG_PRINT(120,"UAF: malloced: ", 0);
        	DEBUG_PRINT_PTR(120,p, 0);
   		DEBUG_PRINT(120,"- ", 0);
        	DEBUG_PRINT_NR(120,newsize, 1);
#endif
#ifdef OOBSUPPORT
		p += OOBSUPPORT;
#endif

                return p;
        }

        return NULL;

}

void *calloc(size_t nmemb, size_t size) {
	size_t newsize;
        void *p;
        mchunkptr myp;

	/* dlsym calls calloc and we call dlsymc
	 * from yyinit to find mmap so we must skip
	 * registrations before yyhash has been
	 * initialized, otherwise we end up in
	 * an endless loop */
	if (!yyhash) return syscalloc(nmemb, size);

#if DEBUGLEVEL <= 120
   	DEBUG_PRINT(120,"UAF: calloc - enter ", 0);
        DEBUG_PRINT_NR(120,nmemb, 0);
   	DEBUG_PRINT(120," ", 0);
        DEBUG_PRINT_NR(120,size, 1);
#endif
	/* we should have int overflow checking here
	 * however the malloc we link to does not have it
	 * so to be able to better measure performance of
	 * our approach we do not check here right now */
        newsize=size*nmemb;

#ifdef OOBSUPPORT
	newsize += OOBSUPPORT;
#endif

        p = syscalloc(1, newsize);

        if (p) {
                myp = mem2chunk(p);
                newsize = chunksize(myp) ;

                labelspace(p, newsize, currlabel);
                currlabel++;
#if DEBUGLEVEL <= 120
   		DEBUG_PRINT(120,"UAF: calloced: ", 0);
        	DEBUG_PRINT_PTR(120,p, 0);
   		DEBUG_PRINT(120,"- ", 0);
        	DEBUG_PRINT_NR(120,newsize, 1);
#endif

#ifdef OOBSUPPORT
		p += OOBSUPPORT;
#endif

                return p;
        }

        return NULL;

}
static inline void unlinkptr();



void free (void *ptr) {
   unsigned int size = 0;
   mchunkptr myp;

   if (!ptr) return;

   if (!yyhash) yyinit();
#if DEBUGLEVEL <= 120
   DEBUG_PRINT(120,"UAF: FREE - enter ", 0);
   DEBUG_PRINT_PTR(120,ptr, 1);
#endif

#ifdef OOBSUPPORT
	ptr -= OOBSUPPORT;
#endif


    myp = mem2chunk(ptr);
    size = chunksize(myp);
    sysfree(ptr);
    unlinkptr(ptr);
    unlinkptr(ptr+4);

    unregisterptrs(ptr, size);
#if DEBUGLEVEL <= 50
   DEBUG_PRINT(50,"UAF: FREE - exit", 1);
#endif
}




// all pointers to realloced memory should be invalidated
// because realloc is not guaranteed to enlarge the current chunk, it might move it


void *realloc(void *ptr, size_t size) {
   void *newptr;
   size_t oldsize, newsize;
   mchunkptr myp;
   LABELTYPE label;

   if (!yyhash) yyinit();
#if DEBUGLEVEL <= 50
   DEBUG_PRINT(50,"UAF: REALLOC - enter ",0);
   DEBUG_PRINT_PTR(50,ptr,0);
   DEBUG_PRINT(50," - ",0);
   DEBUG_PRINT_NR(50,size,1);
#endif

   if (!ptr) {
#if DEBUGLEVEL <= 50
   	DEBUG_PRINT(50,"UAF: REALLOC - exit(1)",1);
#endif
	return malloc(size);
   }

   if (!size) {
	free(ptr);
#if DEBUGLEVEL <= 50
   	DEBUG_PRINT(50,"UAF: REALLOC - exit(2)",1);
#endif
	return 0;
   }

#ifdef OOBSUPPORT
	ptr -= OOBSUPPORT;
	size += OOBSUPPORT;
#endif

   myp = mem2chunk(ptr);
   oldsize = chunksize(myp) ;
   newptr=sysrealloc(ptr, size);
   myp = mem2chunk(newptr);
   newsize = chunksize(myp) ;


   // if a stack frame has been reused and happens to have the same pointers, 
   // they would be invalidated after unreg, and we still need them after the unreg, 
   // so remove them to make sure
   unlinkptr(&newptr);

   // in theory we should invalidate pointers even if its the same, but if the pointer stays the same, 
   // this improves performance / compbitability without introducing errors
   // this check should be disabled when using the mitigation as a testing tool

   if (newptr!= ptr) {
#if DEBUGLEVEL <= 50
	DEBUG_PRINT(50,"UAF: REALLOC", 0);
	DEBUG_PRINT_PTR(50,ptr,0);
	DEBUG_PRINT(50,"!= ", 0);
	DEBUG_PRINT_PTR(50,newptr,1);
#endif
    	unlinkptr(ptr);
	unlinkptr(ptr+4);
        unregisterptrs(ptr, oldsize);
        if (newptr) {
                labelspace(newptr, newsize, currlabel);
                currlabel++;
        }
   } else {
	if (newsize>=oldsize) {
		label=getlabel(newptr);
#if DEBUGLEVEL <= 50
		DEBUG_PRINT(50,"UAF: REALLOC: newsize>oldsize, adding labels", 0);
		DEBUG_PRINT_NR(50,label,1);
#endif
		labelspace(newptr+oldsize, newsize-oldsize,label);
	} else {
#if DEBUGLEVEL <= 50
		DEBUG_PRINT(50,"UAF: REALLOC: newsize<oldsize, removing labels", 1);
		DEBUG_PRINT(50,"UAF: REALLOC: oldsize:", 0);
		DEBUG_PRINT_NR(50,oldsize,0);
		DEBUG_PRINT(50," newsize:", 0);
		DEBUG_PRINT_NR(50,newsize,1);
		DEBUG_PRINT(50,"UAF: REALLOC: oldsize-newsize:", 0);
		DEBUG_PRINT_NR(50,oldsize-newsize,1);
		DEBUG_PRINT(50,"UAF: REALLOC: ptr:", 0);
		DEBUG_PRINT_PTR(50,ptr, 0);
		DEBUG_PRINT(50," newptr:", 0);
		DEBUG_PRINT_PTR(50,newptr, 1);
#endif
    		unlinkptr(ptr);
		unlinkptr(ptr+4);

		unregisterptrs(ptr, oldsize);
#if DEBUGLEVEL <= 50
		DEBUG_PRINT(50,"UAF: REALLOC (after unreg): ptr:", 0);
		DEBUG_PRINT_PTR(50,ptr, 0);
		DEBUG_PRINT(50," newptr:", 0);
		DEBUG_PRINT_PTR(50,newptr, 1);
#endif
                labelspace(newptr, newsize, currlabel++);
	}

   }
#if DEBUGLEVEL <= 50
   DEBUG_PRINT(50,"UAF: REALLOC - exit(3)",1);
#endif

#ifdef OOBSUPPORT
   newptr += OOBSUPPORT;
#endif

   return newptr;
}


// Pointers within the same range (say 32 bytes)
// map to the same hash entry
// When freeing, get indexes for the object + multiples of 32.

/*
static unsigned int getindex(char *obj) {
   unsigned int index;
   index = (((unsigned int) obj) >> BITSHIFT) & (HASHSIZE-1);
   return index;
}
*/

static inline unsigned int getindexlbl(LABELTYPE lbl) {
   return (lbl & (HASHSIZE-1));
}


static inline unsigned int getindexptr(char **ptr) {
   unsigned int index;
   index = (((unsigned int) ptr) >> 2) & (HASHSIZE-1);
   return index;
}


#ifdef DEBUGCHK
static inline void sanitycheckobj(struct hashelement *el) {
	struct hashelement *prev, *next;


	prev = el->prev;
	next = el->next;


	if (prev && prev->next != el) {
		printerr("OBJSANITY: ", "prev->next != el");
		abort();
	}

	if (next && next->prev != el) {
		printerr("OBJSANITY: ", "next->prev != el");
		abort();
	}

	if (next == el) {
		printerr("OBJSANITY: ", "next == el");
		abort();
	}

	if (prev == el) {
		printerr("OBJSANITY: ", "prev == el");
		abort();
	}


}

static inline void sanitycheckptr(struct hashelement *el) {
	struct hashelement *prevptr, *nextptr;
	prevptr = el->ptrprev;
	nextptr = el->ptrnext;

	if (prevptr && prevptr->ptrnext != el) {
		printerr("PTRSANITY", "prevptr->ptrnext != el");
		abort();
	}

	if (nextptr && nextptr->ptrprev != el) {
		printerr("PTRSANITY", "nextptr->ptrprev != el");
		abort();
	}

	if (nextptr == el) {
		printerr("PTRSANITY", "ptrnext == el");
		abort();
	}

	if (prevptr == el) {
		printerr("PTRSANITY", "ptrprev == el");
		abort();
	}


}

static inline void sanitycheck(struct hashelement *el) {
	sanitycheckptr(el);
	sanitycheckobj(el);
}

#endif

static inline void unlinkobjlbl(struct hashelement *el, LABELTYPE objlabel) {
	struct hashelement *prev, *next;
	prev = el->prev;
	next = el->next;

#ifdef DEBUGCHK
	sanitycheckobj(el);
#endif

	if (prev) {
	   	prev->next = next;
	} else {
		yylabelobj[getindexlbl(objlabel)] = next;
	}

	if (next)
		next->prev = prev;


#ifdef DEBUGCHK
	if (prev)
	   sanitycheckobj(prev);
	if (next)
	   sanitycheckobj(next);

#endif


}


static inline void unlinkobjidx(struct hashelement *el, unsigned int idx) {
	struct hashelement *prev, *next;
	prev = el->prev;
	next = el->next;

#ifdef DEBUGCHK
	sanitycheckobj(el);
#endif

	if (prev) {
	   	prev->next = next;
	} else {
		yylabelobj[idx] = next;
	}

	if (next)
		next->prev = prev;

#ifdef DEBUGCHK
	if (prev)
	   sanitycheckobj(prev);
	if (next)
	   sanitycheckobj(next);

#endif
}

static inline void unlinkptridx(struct hashelement *el, unsigned int index) {
	struct hashelement *prevptr, *nextptr;
	prevptr = el->ptrprev;
	nextptr = el->ptrnext;

#ifdef DEBUGCHK
	sanitycheckptr(el);
#endif

	if (prevptr) {
	   	prevptr->ptrnext = nextptr;
	} else {
		yyhashptr[index] = nextptr;
	}

	if (nextptr)
		nextptr->ptrprev = prevptr;

#ifdef DEBUGCHK
	if (prevptr)
	   sanitycheckptr(prevptr);
	if (nextptr)
	   sanitycheckptr(nextptr);
#endif


}


static inline void unlinkptr_p(struct hashelement *el, char **p) {
	unsigned int indexptr;
	struct hashelement *prevptr, *nextptr;

	prevptr = el->ptrprev;
	nextptr = el->ptrnext;


#ifdef DEBUGCHK
	sanitycheckptr(el);
#endif

	if (prevptr) {
	   	prevptr->ptrnext = nextptr;
	} else {
        	indexptr = getindexptr(p);
		yyhashptr[indexptr] = nextptr;
	}

	if (nextptr)
		nextptr->ptrprev = prevptr;

#ifdef DEBUGCHK
	if (prevptr)
	   sanitycheckptr(prevptr);
	if (nextptr)
	   sanitycheckptr(nextptr);
#endif


}

static inline void unlinkptr(char **p) {
	unsigned int ptrindex;
	struct hashelement *newel;
	char *p_bptr;

   	ptrindex = getindexptr(p);
   	newel = yyhashptr[ptrindex];

        while (newel) {
        	p_bptr = newel->bptr;
        	if (p_bptr == (char *) p) {
			unlinkptridx(newel, ptrindex);
		    	unlinkobjlbl(newel, newel->objlbl);
			deleteelement(newel);
			return;
		}
		newel = newel->ptrnext;
	}

}

static inline void inserthashobjlbl(struct hashelement *newel, LABELTYPE objlabel) {
   	struct hashelement *el;

	el = yylabelobj[getindexlbl(objlabel)];

	// remove me
#ifdef DEBUGCHK
	while (el) {
	  if (el == newel) {
		printerr("INSERTHASHOBJLBL", "inserting element that's already there");
		abort();
	  }
	  el = el->next;
	}
	el = yylabelobj[getindexlbl(objlabel)];
#endif


	if (el)
		el->prev = newel;
	newel->next = el;
	newel->prev = 0;
	yylabelobj[getindexlbl(objlabel)] = newel;

}

static inline void inserthashptridx(struct hashelement *newel, unsigned int index) {
   struct hashelement *el;

   el = yyhashptr[index];

#ifdef DEBUGCHK
	while (el) {
	  if (el == newel) {
		printerr("INSERTHASHPTRIDX", "inserting element that's already there");
		abort();
	  }
	  el = el->ptrnext;
        }
   	el = yyhashptr[index];
#endif

   if (el)
	el->ptrprev = newel;
   newel->ptrnext = el;
   newel->ptrprev = 0;
   yyhashptr[index] = newel;



}

static inline void inserthashptr(struct hashelement *newel, char **p) {
   unsigned int index;
   index = getindexptr(p);
   inserthashptridx(newel, index);
}


static inline void hashaddelement(char *obj, char **p) {
   unsigned int index, c_index, p_index, ptrindex;
   struct hashelement *el, *newel, *ptrel, *next;
   char *c_bptr, *c_obj;
   char *p_bptr, *p_obj;

   LABELTYPE ptrlbl, objlbl;

#ifdef DEBUGCHK
   struct hashelement *prev = 0;
#endif

   if ((unsigned int) obj >= 0xC0000000) {
	return;
   }


   objlbl = getlabel(obj);
   // no object label means this memory is not being tracked
   // obj = 0, will also return 0 for objlbl so no need for check later on
   if (!objlbl) {
#if DEBUGLEVEL <= 160
   	DEBUG_PRINT(160,"UAF: HASHADD objlbl is 0, returning",1);
#endif
	return;
   }
#if DEBUGLEVEL <= 160
   DEBUG_PRINT(160,"UAF: HASHADD - enter *",0);
   DEBUG_PRINT_PTR(160,p,0);
   DEBUG_PRINT(160," = ",0);
   DEBUG_PRINT_PTR(160,obj,1);
#endif

   ptrindex = getindexptr(p);

#if DEBUGLEVEL <= 160
   DEBUG_PRINT(160,"UAF: HASHADD - ptrindex: ",0);
   DEBUG_PRINT_PTR(160,ptrindex,1);
#endif
   newel = yyhashptr[ptrindex];

#if DEBUGLEVEL <= 160
     DEBUG_PRINT(160,"UAF: HASHADD - loop index: ",0);
#endif

   while (newel) {
#if DEBUGLEVEL <= 160
        DEBUG_PRINT_PTR(160,newel,0);
   	DEBUG_PRINT(160,", ",0);
#endif

#ifdef DEBUGCHK
	if (prev == newel) {
		printerr("HASHADD: ", "ENDLESS LOOP");
		abort();
	}
	prev = newel;
#endif

        p_bptr = newel->bptr;
        if (p_bptr == (char *) p) {
#if DEBUGLEVEL <= 160
   		DEBUG_PRINT(160," ",1);
   		DEBUG_PRINT(160,"UAF: HASHADD: Found element",1);
#endif

		ptrlbl = newel->objlbl;

		if (ptrlbl == objlbl)
			return;
		// should be able to remove this (no more checks on obj)
//                newel->obj = obj;
//  out of bounds support
/*
		if (ptrlbl == objlbl-1 || ptrlbl == objlbl+1) {
			// write(2, "ptr oob\n",8);
			// pointer has gone out of bounds, stop tracking it
      			unlinkptr_p(newel, p_bptr);
	    		unlinkobjlbl(newel, ptrlbl);
			sysfree(newel);
			return;
		}
*/
		newel->objlbl = objlbl;

	    	unlinkobjlbl(newel, ptrlbl);
		inserthashobjlbl(newel, objlbl);

                return;


        } else {

            newel = newel->ptrnext;
        }
   }
#if DEBUGLEVEL <= 160
   DEBUG_PRINT(160," ",1);
   DEBUG_PRINT(160,"UAF: HASHADD: no element found, adding new",1);
#endif


// no need to check for a previous pointer to this object anymore as the previous pointer lookup should have found this
/*
   newel = el;
   while (newel) {
        if (newel->bptr == p) {
                newel->obj = obj;
                return;
        }
        newel = newel->next;
   } */

   newel = getnewelement();
/* sysmalloc(sizeof(struct hashelement));
   if (!newel) {
 	printerr("ERROR: ", "couldn't allocate memory for element\n");
        exit(-1);
   } */

   // should be able to remove this (no more checks on obj)
//   newel->obj = obj;
   newel->objlbl = objlbl;
   newel->bptr = p;


   inserthashobjlbl(newel, objlbl);
   inserthashptridx(newel, ptrindex);

}

static inline char *getinvalidpointer(char *pobj) {
	unsigned int invalid;
	invalid = (((unsigned int) pobj) | ((unsigned int) KERNELMEM));
#if DEBUGLEVEL <= 120
	DEBUG_PRINT(120,"UAF: GETINVALID: invalidating pointer: ",0);
	DEBUG_PRINT_PTR(120,invalid,1);
#endif
	return (char *) invalid;

}

static inline void hashvoidelementlbl(LABELTYPE objlbl, char *obj) {
   struct hashelement *prev = 0;
   struct hashelement *next;
   char **bptr;
   struct hashelement *el;
   char *pobj;
   LABELTYPE ptrlbl=0;
   unsigned int objidx;

   objidx=getindexlbl(objlbl);

   el = yylabelobj[objidx];

   while (el) {
	next = el->next;
	if (el->objlbl != objlbl) {
		el = next;
		continue;
	}
	bptr = el->bptr;
	if (bptr && pagelive(bptr)) {
	   pobj = *bptr;
	   if (((unsigned int) pobj) < 0xC0000000) {
	   	ptrlbl = getlabel(pobj);
	   	if (ptrlbl == objlbl) {

		  //ptrlbl2 = getlabel(bptr);
		  // freeing in free object shouldn't happen
		  /* if (ptrlbl2 == objlbl) {
	   		  DEBUG_PRINT(160,"UAF: HASHVOID: objlbls equal: ",0);
			  DEBUG_PRINT_NR(160, ptrlbl, 1);
		  } */

#if DEBUGLEVEL <= 120
   		  DEBUG_PRINT(120,"UAF: HASHVOID: invalidating pointer: *",0);
   		  DEBUG_PRINT_PTR(120,bptr,0);
   		  DEBUG_PRINT(120," = ",0);
   		  DEBUG_PRINT_PTR(120,pobj,1);
#endif

		  *bptr = getinvalidpointer(pobj);
	   	}
	   }
	}
#if DEBUGLEVEL <= 200
   		  DEBUG_PRINT(200,"HVOID: uptr_p:",0);
   		  DEBUG_PRINT_PTR(200,bptr,0);
   		  DEBUG_PRINT(200," obj:",0);
   		  DEBUG_PRINT_PTR(200,obj,0);
   		  DEBUG_PRINT(200," objptr:",0);
   		  DEBUG_PRINT_PTR(200,pobj,0);
   		  DEBUG_PRINT(200," ptrlbl:",0);
   		  DEBUG_PRINT_PTR(200,ptrlbl,0);
   		  DEBUG_PRINT(200," objbl:",0);
   		  DEBUG_PRINT_PTR(200,objlbl,0);
   		  DEBUG_PRINT(200," stored objbl:",0);
   		  DEBUG_PRINT_PTR(200,el->objlbl,1);

#endif
	// need to do this, because we can have pointers to multiple objects bucketed 
	unlinkobjidx(el, objidx);

	unlinkptr_p(el, bptr);

	deleteelement(el);
	el = next;
   }
//   yylabelobj[getindexlbl(objlbl)] = 0;
}


static inline void hashvoidelement(char *obj, char *objend) {
   unsigned int idx, idxptr;
   struct hashelement *el;
   struct hashelement *prev = 0;
   struct hashelement *next;
   char **bptr;
   char *pobj;
   char *elobj;
   char *invalidptr;
   LABELTYPE objlbl=0, ptrlbl=0;
#if DEBUGLEVEL <= 120
   DEBUG_PRINT(120,"UAF: HASHVOID - enter ",0);
   DEBUG_PRINT_PTR(120,obj,0);
   DEBUG_PRINT(120," - ",0);
   DEBUG_PRINT_PTR(120,objend,1);
#endif
   if (!yyhash) yyinit();

   objlbl = getlabel(obj);
   if (!objlbl) return;

   hashvoidelementlbl(objlbl, obj);
}


void ( __attribute__((__constructor__(101))) inituaf)() {
#ifdef DEBUG
//	write(2, "init\n", 5);
#endif
#ifdef GLOBALOPT
        globalmemend = (char *) sysmalloc(0);
        free(globalmemend);
#endif
	yyinit();
}

#ifdef STATS
void (__attribute__((__destructor__(101))) enduaf)() {
	fprintf(stderr, "Total calls to doregister: %llu\n", total);
}
#endif

static inline void doregister(char **p, char *obj) {
#ifdef GLOBALOPT
    if (obj >globalmembegin && obj<globalmemend) {
	return;
    }
#endif
#ifdef STATS
   total++;
#endif
#if DEBUGLEVEL <= 120
   DEBUG_PRINT(120,"regptr: p: ",0);
   DEBUG_PRINT_PTR(120,p,0);
   DEBUG_PRINT(120,", obj: ",0);
   DEBUG_PRINT_PTR(120,obj,1);
#endif
   hashaddelement(obj, p);
}

void registerptrobj(char **p, char *obj) {
   if (!p) return;
   doregister(p, obj);
}

// Receives a pointer to a pointer
// That pointer points to an object
// When the object is freed, we will invalidate all pointers to that object

void registerptr (char **p) {
   char *obj = 0;

   if (!p) return;

   obj = (char *) *p;

   doregister(p, obj);
}

void unregisterptrs(char *obj, unsigned int size) {
//   int iterations;
   char *objend;
#if DEBUGLEVEL <= 120
   DEBUG_PRINT(120,"UNREG: obj: ",0);
   DEBUG_PRINT_PTR(120,obj,0);
   DEBUG_PRINT(120,", size: ",0);
   DEBUG_PRINT_NR(120,size,1);
#endif
   objend = obj+size;

   hashvoidelement(obj, objend);

}


void registerstackptrs() {
#ifdef NOSTACK
   return ;
#endif
#if __x86_64__
/*   unsigned long long *stackend;
   unsigned long long *stackstart;
   unsigned long long tmp;
   asm("\t mov %%rbp,%0" : "=r"(tmp));
   stackend = (unsigned long long *) *((unsigned long long *)tmp);
   stackstart = (unsigned long long *) (tmp); */
#else
   unsigned long tmp;
   char *stackend;
//   char *prevend;
   char *stackstart;

//   LABELTYPE endlabel;
//   LABELTYPE prevendlabel;

   asm("\t movl %%ebp,%0" : "=r"(tmp));
   stackend = ((char *) *((unsigned long *)tmp)) + 8;
   stackstart = ((char *) (tmp)) + 8;


#endif

#if DEBUGLEVEL <= 180
   DEBUG_PRINT(180, "REGSTACK: stackstart: ", 0);
   DEBUG_PRINT_PTR(180,stackstart,0);
   DEBUG_PRINT(180, " stackend: ", 0);
   DEBUG_PRINT_PTR(180,stackend,1);

#endif

   labelspace((char *) stackstart, ((char *)stackend) - ((char *) stackstart), currlabel);
   currlabel++;
}

void unregisterstackptrs() {
#ifdef NOSTACK
   return ;
#endif
#if __x86_64__
/*   unsigned long long *stackend;
   unsigned long long *stackstart;
   unsigned long long tmp;
   asm("\t mov %%rbp,%0" : "=r"(tmp));
   stackend = (unsigned long long *) *((unsigned long long *)tmp);
   stackstart = (unsigned long long *) (tmp); */
#else
   unsigned long tmp;
   char *stackend;
   char *stackstart;

   asm("\t movl %%ebp,%0" : "=r"(tmp));
   stackend = ((char *) *((unsigned long *)tmp)) + 8;
   stackstart = ((char *) (tmp)) + 8;

#endif
#if DEBUGLEVEL <= 180
   DEBUG_PRINT(180, "UNREGSTACK: stackstart: ", 0);
   DEBUG_PRINT_PTR(180,stackstart,0);
   DEBUG_PRINT(180, " stackend: ", 0);
   DEBUG_PRINT_PTR(180,stackend,1);
#endif
   unregisterptrs((char *) stackstart, ((char *)stackend) - ((char *) stackstart));
}


void updatestackptrs() {
   unsigned long tmp;
   char *stackend;
   char *stackstart;
   LABELTYPE stacklbl;


   asm("\t movl %%ebp,%0" : "=r"(tmp));
   stackend = ((char *) *((unsigned long *)tmp)) + 8;
   stackstart = ((char *) (tmp)) + 8;

   stacklbl = getlabel(stackend-1);

#if DEBUGLEVEL <= 180
   DEBUG_PRINT(180, "UPDATESTACK: stackstart: ", 0);
   DEBUG_PRINT_PTR(180,stackstart,0);
   DEBUG_PRINT(180, " stackend: ", 0);
   DEBUG_PRINT_PTR(180,stackend,0);
   DEBUG_PRINT(180, " stacklabel: ", 0);
   DEBUG_PRINT_PTR(180,stacklbl,1);
#endif

// need to get label
   labelspace((char *) stackstart, ((char *)stackend) - ((char *) stackstart), stacklbl);

/*
   prevend = (char *) *((unsigned long *)(stackend-8));

   if (prevend) {
	prevend += 8;
   	endlabel = getlabel(stackend);
   	prevendlabel = getlabel(prevend-1);
   }
   if (prevend) {
   	DEBUG_PRINT(180, "REGSTACK: prevend: ", 0);
   	DEBUG_PRINT_PTR(180,prevend,0);
   	DEBUG_PRINT(180, " endlabel: ", 0);
	DEBUG_PRINT_NR(180,endlabel,0);
   	DEBUG_PRINT(180, " prevendlabel: ", 0);
	DEBUG_PRINT_NR(180,prevendlabel,1);
   }
*/

}
