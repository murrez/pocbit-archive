CC ?= gcc
CFLAGS_BASE = -Wall -Wextra -std=gnu99 -I$(INC_DIR)
CFLAGS_RELEASE = $(CFLAGS_BASE) -O3
CFLAGS_DEBUG   = $(CFLAGS_BASE) -g -O0

CFLAGS ?= $(CFLAGS_RELEASE)

TARGET = drifter
SRC_DIR = src
INC_DIR = headers
BUILD_DIR = build

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
DEPS = $(OBJS:.o=.d)

.PHONY: all debug clean rebuild

all: $(TARGET)

debug:
	@$(MAKE) CFLAGS="$(CFLAGS_DEBUG)" all

$(TARGET): $(OBJS)
	@echo "🔗 Linking binary: $@"
	@$(CC) $(OBJS) -o $@
	@echo "✨ Build complete: $(TARGET)"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "🔨 Compiling $<..."
	@$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR) $(TARGET)
	@echo "✨ Clean complete."

rebuild: clean all
strip:
	strip --strip-unneeded $(TARGET)