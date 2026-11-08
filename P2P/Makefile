# Portable build for p2pNet
#
# Works on Linux (gcc/clang or musl-gcc) and macOS (clang).
#
#   make            # build agent + keygen
#   make agent      # build p2p_agent
#   make tools      # build keygen
#   make clean
#
# Optional:
#   make STATIC=1   # static binary (Linux + musl-gcc)
#   make CC=clang   # override compiler
#   make DEBUG=1    # -O0 -g -fsanitize=address

UNAME_S := $(shell uname -s)

CC      ?= cc
CXX     ?= c++
BUILD   := build

CFLAGS  := -std=c11 -Icore/include -DPOSIX -DNDEBUG
CFLAGS  += -O2 -Wall -Wextra
CFLAGS  += -Wno-unused-parameter -Wno-sign-compare
CFLAGS  += -Wno-macro-redefined -Wno-incompatible-pointer-types
CFLAGS  += -MMD -MP

ifeq ($(DEBUG),1)
CFLAGS  := -std=c11 -Icore/include -DPOSIX -O0 -g -Wall -Wextra \
           -Wno-unused-parameter -Wno-sign-compare -Wno-macro-redefined \
           -Wno-incompatible-pointer-types -fsanitize=address -MMD -MP
LDFLAGS := -fsanitize=address
endif

LDLIBS  := -lpthread -lm

# Optional libcurl: enables HTTPS (Discord webhooks) and the full HTTP client.
# The plain-HTTP client is built in, so this dependency is not required.
CURL_CFLAGS := $(shell pkg-config --cflags libcurl 2>/dev/null)
CURL_LIBS   := $(shell pkg-config --libs libcurl 2>/dev/null)
ifneq ($(strip $(CURL_LIBS)),)
CFLAGS  += $(CURL_CFLAGS) -DP2P_HAVE_CURL=1
endif

AGENT_BIN  := guardian_p2p
KEYGEN_BIN := keygen

# epoll/accept4/pipe2 shims are only needed on non-Linux platforms
ifeq ($(UNAME_S),Linux)
COMPAT_SRC :=
else
COMPAT_SRC := core/compat/posix_compat.c
endif

CORE_SRC := \
	third_party/monocypher/monocypher.c \
	$(COMPAT_SRC) \
	core/hpv/state.c \
	core/hpv/util.c \
	core/crypto/crypto.c \
	core/hpv/guard.c \
	core/dht/dht.c \
	core/hpv/registry.c \
	core/gossip/gossip.c \
	core/dht/bt_dht.c \
	core/overlay/overlay.c \
	core/overlay/udp.c \
	core/overlay/attack_engine.c \
	core/overlay/killer_locker.c \
	core/hpv/transport.c \
	core/hpv/iot_profile.c \
	core/hpv/watchdog.c \
	core/net/net_tools.c

AGENT_SRC := $(CORE_SRC) main/main.c
AGENT_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(AGENT_SRC))
AGENT_DEP := $(AGENT_OBJ:.o=.d)

KEYGEN_SRC := tools/keygen.c third_party/monocypher/monocypher.c
KEYGEN_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(KEYGEN_SRC))

ifeq ($(STATIC),1)
LDFLAGS += -static
endif

.PHONY: all agent tools clean help

all: agent tools

agent: $(AGENT_BIN)

tools: $(KEYGEN_BIN)

$(AGENT_BIN): $(AGENT_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) $(AGENT_OBJ) $(LDFLAGS) $(LDLIBS) $(CURL_LIBS) -o $@
	@ls -lh $@

$(KEYGEN_BIN): $(KEYGEN_OBJ)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) $(KEYGEN_OBJ) $(LDFLAGS) $(LDLIBS) -o $@
	@ls -lh $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@rm -rf $(BUILD) $(AGENT_BIN) $(KEYGEN_BIN)
	@echo "Cleaned"

help:
	@echo "Targets:"
	@echo "  make            Build agent + keygen"
	@echo "  make agent      Build $(AGENT_BIN)"
	@echo "  make tools      Build $(KEYGEN_BIN)"
	@echo "  make clean      Remove build artifacts"
	@echo ""
	@echo "Options:"
	@echo "  STATIC=1        Static link (Linux + musl-gcc)"
	@echo "  DEBUG=1         ASan debug build"
	@echo "  CC=clang        Override compiler"

-include $(AGENT_DEP) $(KEYGEN_OBJ:.o=.d)
