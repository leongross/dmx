CFLAGS = -Wall -DDEBUG -ggdb
LIBS = -L/usr/include/openssl -lssl -lcrypto -luuid
CC = gcc

all: mkmint


clean:
	-rm mkmint


mkmint: mkmint.c mkmint.h
#ifeq ($(STATIC),1)
#	$(CFLAGS) := -static
#endif
	$(CC) mkmint.c -o mkmint $(CFLAGS) $(LIBS) 
