# Makefile
# 19-Nov-11 Markku-Juhani O. Saarinen <mjos@iki.fi>

BINARY          = sha3test
OBJS     	= sha3.o main.o
DIST            = tiny_sha3

CC              = gcc
CFLAGS		= -Wall -O3
LIBS            =
LDFLAGS         =
INCLUDES	=

$(BINARY):      $(OBJS)
		$(CC) $(LDFLAGS) -o $(BINARY) $(OBJS) $(LIBS)

.c.o:
		$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
		rm -rf $(DIST)-*.txz $(OBJS) $(BINARY) *~ 

dist:		clean
		cd ..; \
		tar cfvJ $(DIST)/$(DIST)-`date -u "+%Y%m%d%H%M00"`.txz \
			$(DIST)/*
