.phony: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CXX ?= $(CC)

BIN := ../bin/mp4dumper.elf
SRC := $(wildcard *.c)
OBJS = $(SRC:.c=.o)
DEPFILES = $(OBJS:.o=.d)

CXXFLAGS := -std=c++23 -Wall -I../include -march=znver2 -g0 -O3 -flto=full -MMD -MP
LDFLAGS := -L../lib -lmp4rw

%.o: %.c
	$(CXX) $(CXXFLAGS) -x c++ -c -o $@ $<

$(BIN): $(OBJS)
	mkdir -p $(dir $(BIN))
	$(CXX) $(LDFLAGS) -o $@ $^


all: $(BIN)

clean:
	rm -f $(BIN) $(OBJS) $(DEPFILES)

-include $(DEPFILES)

