GCC=gcc
LIB_SRC=libfreesentry.c
LIB_OBJ= $(patsubst %.c,%.o,$(LIB_SRC))
LIB_SO= $(patsubst %.o,%.so,$(LIB_OBJ))
LIB_DLSRC=libdlmalloc32b.c
LIB_DLOBJ= $(patsubst %.c,%.o,$(LIB_DLSRC))
LIB_DLSO= $(patsubst %.o,%.so,$(LIB_DLOBJ))

LIBPARAM=-DDEBUG -g -fPIC -fno-omit-frame-pointer
#LIBPARAM=-g -fPIC -fno-omit-frame-pointer
#LIBPARAM=-O3 -fPIC  -fno-omit-frame-pointer

all: library

library: $(LIB_SO) $(LIB_DLSO)

install: $(LIB_SO) $(LIB_DLSO)
	mkdir -p /usr/local/lib
	mkdir -p /usr/local/share/freesentry/
	cp $(LIB_SO) /usr/local/lib/
	cp $(LIB_DLSO) /usr/local/lib/
	cp callmodel.res /usr/local/share/freesentry/
	cp resolvecalls.py /usr/local/bin/

$(LIB_OBJ): $(LIB_SRC)
	$(GCC) $(LIBPARAM) -c $< 

$(LIB_SO): $(LIB_OBJ)
	$(GCC) $(LIBPARAM) -shared -Wl,-soname,$@ -o $@ $^ -lc -ldl
	rm $^

$(LIB_DLOBJ): $(LIB_DLSRC)
	$(GCC) $(LIBPARAM) -c $< 

$(LIB_DLSO): $(LIB_DLOBJ)
	$(GCC) $(LIBPARAM) -shared -Wl,-soname,$@ -o $@ $^ -lc -ldl
	rm $^

clean:
	rm -f $(LIB_SO) $(LIB_DLSO)
