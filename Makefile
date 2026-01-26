# vault.deadlight Makefile
# Minimal, portable, static binary target

NAME       = deadlight_vault
CC         ?= gcc
CFLAGS     = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS    =
LDLIBS     = -lcrypto -lpthread -ldl -lm

# Debug vs Release
ifeq ($(DEBUG),1)
    CFLAGS += -g -Og -DDEBUG -fsanitize=address
    LDFLAGS += -fsanitize=address
else
    CFLAGS += -DNDEBUG -s
endif

# === Directories ==============================================================

SRC_DIR     = src
INC_DIR     = include
SQLITE_DIR  = vendor/sqlite

# === Source files =============================================================

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/vault.c \
       $(SRC_DIR)/cli.c \
       $(SRC_DIR)/crypto_vault.c \
       $(SRC_DIR)/pbkdf2_shim.c \
       $(SQLITE_DIR)/sqlite3.c

OBJS = $(SRCS:.c=.o)
TARGET = $(NAME)

# === Includes =================================================================

INCLUDES = -I$(INC_DIR) -I$(SQLITE_DIR)

# === Compiler flags ===========================================================

# SQLite compile-time options (smaller binary)
CFLAGS += -DSQLITE_OMIT_LOAD_EXTENSION \
          -DSQLITE_OMIT_DEPRECATED \
          -DSQLITE_THREADSAFE=0 \
          -DSQLITE_DEFAULT_MEMSTATUS=0

# === Rules ====================================================================

.PHONY: all clean test install static cross-arm64

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking $@..."
	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LDLIBS)
	@echo "Build complete: $@ ($$(du -h $@ | cut -f1))"

%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# === SQLite fetch =============================================================

$(SQLITE_DIR)/sqlite3.c:
	@echo "Fetching SQLite amalgamation..."
	@mkdir -p $(SQLITE_DIR)
	@cd $(SQLITE_DIR) && \
	  wget -q https://www.sqlite.org/2025/sqlite-amalgamation-3480000.zip && \
	  unzip -q sqlite-amalgamation-*.zip && \
	  mv sqlite-amalgamation-*/* . && \
	  rm -rf sqlite-amalgamation-* *.zip
	@echo "SQLite ready"

sqlite: $(SQLITE_DIR)/sqlite3.c

# === Clean ====================================================================

clean:
	@echo "Cleaning..."
	@rm -f $(OBJS) $(TARGET) *.o src/*.o $(SQLITE_DIR)/*.o
	@echo "Clean complete"

distclean: clean
	@echo "Removing SQLite..."
	@rm -rf $(SQLITE_DIR)
	@echo "Distribution clean complete"

# === Testing ==================================================================

test: $(TARGET)
	@echo "Running basic tests..."
	@./$(TARGET) --version || true
	@./$(TARGET) --help || true
	@echo "Manual test: ./$(TARGET) init"

# === Installation =============================================================

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin

install: $(TARGET)
	@echo "Installing to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@install -m 755 $(TARGET) $(BINDIR)/
	@echo "Installed: $(BINDIR)/$(TARGET)"

uninstall:
	@echo "Uninstalling..."
	@rm -f $(BINDIR)/$(TARGET)
	@echo "Uninstalled"

# === Static build =============================================================

static: CFLAGS += -static
static: LDFLAGS += -static
static: all
	@echo "Static build complete"

# === Cross-compile ============================================================

cross-arm64:
	@echo "Cross-compiling for ARM64..."
	$(MAKE) CC=aarch64-linux-gnu-gcc \
	        CFLAGS="$(CFLAGS) -march=armv8-a" \
	        LDFLAGS="$(LDFLAGS) -static"
	@echo "ARM64 build complete"

# === Size report ==============================================================

size: $(TARGET)
	@echo "Binary size breakdown:"
	@size $(TARGET)
	@echo
	@echo "Disk usage:"
	@du -h $(TARGET)
	@echo
	@echo "Stripped size:"
	@strip --strip-all $(TARGET) -o $(TARGET).stripped
	@du -h $(TARGET).stripped
	@rm -f $(TARGET).stripped

# === Dependencies =============================================================

$(SRC_DIR)/main.o: $(INC_DIR)/vault.h $(INC_DIR)/cli.h
$(SRC_DIR)/vault.o: $(INC_DIR)/vault.h $(INC_DIR)/crypto_vault.h $(SQLITE_DIR)/sqlite3.h
$(SRC_DIR)/cli.o: $(INC_DIR)/cli.h $(INC_DIR)/vault.h
$(SRC_DIR)/crypto_vault.o: $(INC_DIR)/crypto_vault.h