CC=g++
SOURCES=dgk.cc maurer.cc gdsa.cc random.cc dgk_keygen.cc
OBJECTS=$(SOURCES:.cc=.o)
LIBS=-lgmp -lm

#INCLUDES=/usr/include/python2.6/ 
INCLUDES=
EXEC=libdgk.so
LIBS= -lm -lgmp
#CFLAGS=-O3 -fomit-frame-pointer -mfpmath=sse -msse3 -Wall
LIBBASENAME=libdgk.so
SONAME=libdgk.so.1
OSONAME=libdgk.so.1.0.1
CFLAGS=-O3 -Wall -c -fPIC
PFLAGS= -g -pg -fPIC
LFLAGS= -shared -Wl,-soname,$(SONAME) -o $(OSONAME)
REV=`bzr version-info --custom --template {revno}`
TAG=-0.1r
LIBDIR=/usr/local/lib/

all:
	make main

main:
	$(CC) $(CFLAGS) $(SOURCES) -I$(INCLUDES) $(LIBS)
	$(CC) $(LFLAGS) $(OBJECTS) 


debg:
	$(CC) $(PFLAGS) $(SOURCES) -I$(INCLUDES) $(LIBS)
	$(CC) $(LFLAGS) $(OBJECTS) 


install:	
	cp $(OSONAME) $(LIBDIR)
	if ! test -e $(LIBDIR)$(OSONAME) ; then \
ln -s $(LIBDIR)$(OSONAME) $(LIBDIR)$(SONAME) ; fi
	if ! test -e $(LIBDIR)$(LIBBASENAME) ; then \
ln -s $(LIBDIR)$(OSONAME) $(LIBDIR)$(LIBBASENAME) ; fi
	ldconfig

clean:
	rm -rf $(EXEC) $(OBJECTS) $(OSONAME)

export:
	bzr export ../libdgk-$(TAG)${REV}.tar