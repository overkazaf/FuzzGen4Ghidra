# SO Audit Demo — Simulated Android/Linux native library
#
# Usage:
#   make            # build everything (uses .dylib on macOS, .so on Linux)
#   make audit      # run all PoC exploits
#   make asan       # build + run with ASan
#   make clean

CC = clang
CFLAGS = -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0

UNAME := $(shell uname)
ifeq ($(UNAME),Darwin)
  LIB_EXT = dylib
  SHARED_FLAGS = -shared
else
  LIB_EXT = so
  SHARED_FLAGS = -shared -fPIC
endif

LIB = libnative_parser.$(LIB_EXT)
LIB_ASAN = libnative_parser_asan.$(LIB_EXT)
AUDIT = audit_demo

all: $(LIB) $(AUDIT)

$(LIB): libnative_parser.c
	$(CC) $(SHARED_FLAGS) $(CFLAGS) -o $@ $<

$(LIB_ASAN): libnative_parser.c
	$(CC) $(SHARED_FLAGS) -g -O0 -fsanitize=address -fno-omit-frame-pointer -o $@ $<

$(AUDIT): audit_demo.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

audit: $(AUDIT) $(LIB)
	@echo "=== Running SO Audit Demo ==="
	./$(AUDIT)

asan: $(LIB_ASAN) audit_demo.c
	$(CC) -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-o audit_asan audit_demo.c -ldl
	@echo "=== Running with ASan ==="
	-DYLD_INSERT_LIBRARIES= ./audit_asan || true

clean:
	rm -f $(LIB) $(LIB_ASAN) $(AUDIT) audit_asan
	rm -rf *.dSYM

.PHONY: all audit asan clean
