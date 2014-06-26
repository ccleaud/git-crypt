CXX := c++
CXXFLAGS := -Wall -pedantic -Wextra -Wno-long-long -Wunreachable-code -Wmissing-declarations -Wswitch-default -fexceptions -Os -march=nocona
LDFLAGS := -lcrypto -lgdi32 -s
PREFIX := /usr/local
OBJFILES = git-crypt.o commands.o crypto.o gpg.o key.o util.o

all: git-crypt

git-crypt: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

util.o: util.cpp util-unix.cpp util-win32.cpp

clean:
	rm -f *.o git-crypt

.PHONY: all clean install

