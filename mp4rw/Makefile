.phony: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CXX ?= $(CC)

LIB := ../lib/libmp4rw.a
SRC := $(wildcard *.c)
OBJS = $(SRC:.c=.o)
DEPFILES = $(OBJS:.o=.d)

CXXFLAGS := -std=c++23 -Wall -I../include -march=znver2 -g0 -O3 -flto=full -MMD -MP

all: $(LIB)

%.o: %.c
	$(CXX) $(CXXFLAGS) -x c++ -c -o $@ $<

$(LIB): $(OBJS)
	mkdir -p $(dir $(LIB))
	$(AR) -rsc $@ $^

clean:
	rm -f $(LIB) $(OBJS) $(DEPFILES)

-include $(DEPFILES)

