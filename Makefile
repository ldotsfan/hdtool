CC      = gcc
CFLAGS  = -DXbox -Wall -O2 -D_GNU_SOURCE -I include -I. -I/usr/src/linux/include
LDFLAGS = -s
STATIC  =

PROGS   = hdtool
all: clean $(PROGS)

hdtool: lib/xbox/xboxlib.o  lib/eeprom/BootHddKey.o lib/crypto/rc4.o  lib/crypto/sha1.o hdtool.o
	$(CC) $(LDFLAGS) -o $@ lib/eeprom/BootHddKey.o  hdtool.o  lib/crypto/rc4.o  lib/crypto/sha1.o  lib/xbox/xboxlib.o
clean:
	rm -f hdtool *.o lib/xbox/*.o lib/crypto/*.o lib/eeprom/*.o

install:
	cp hdtool /usr/sbin
