# FILE: Makefile
CC ?= cc
CPPFLAGS += -D_GNU_SOURCE -I.
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
STATIC ?= 0
ifeq ($(STATIC),1)
LDFLAGS += -static
endif
LDLIBS += -pthread

TARGET := raw-server
SOURCES := raw_server.c crypto.c config_data.c

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) $(LDLIBS)

check:
	$(CC) $(CPPFLAGS) $(CFLAGS) -fsyntax-only $(SOURCES)

clean:
	rm -f $(TARGET)
