# FuzzGen4Ghidra Demo — vulnerable library + PoC exploit
#
# Usage:
#   make            # build everything
#   make poc        # run the 4-level PoC
#   make asan       # run with ASan (detects overflow without exploit)
#   make clean

CC = clang
CFLAGS_VULN = -shared -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0
CFLAGS_POC  = -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0
CFLAGS_ASAN = -shared -g -O0 -fsanitize=address -fno-omit-frame-pointer

all: libdemo.dylib poc_exploit harness_asan

libdemo.dylib: libdemo.c
	$(CC) $(CFLAGS_VULN) -o $@ $<

libdemo_asan.dylib: libdemo.c
	$(CC) $(CFLAGS_ASAN) -o $@ $<

poc_exploit: poc_demo.c libdemo.dylib
	$(CC) $(CFLAGS_POC) -o $@ $< -ldl

harness_asan: poc_demo.c libdemo_asan.dylib
	$(CC) -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
		-DUSE_ASAN_LIB -o $@ $< -ldl

poc: poc_exploit libdemo.dylib
	@echo "=== Running PoC (4 levels) ==="
	./poc_exploit

asan: libdemo_asan.dylib
	@echo "=== ASan detection demo ==="
	@echo "Building simple test driver..."
	@printf '#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n#include <dlfcn.h>\ntypedef int (*fn_t)(const unsigned char*,int);\nint main(){\nvoid*l=dlopen("./libdemo_asan.dylib",RTLD_LAZY);\nfn_t f=dlsym(l,"process_header");\nuint8_t pkt[1007];\nmemset(pkt,0,sizeof(pkt));\npkt[0]=0xDE;pkt[1]=0xAD;pkt[2]=0xBE;pkt[3]=0xEF;pkt[4]=1;\npkt[5]=0xE8;pkt[6]=0x03;\nmemset(pkt+7,0x42,1000);\nprintf("Calling process_header with payload_len=1000...\\n");\nf(pkt,1007);\nprintf("Returned (should not reach here)\\n");\nreturn 0;\n}' > /tmp/_asan_test.c
	$(CC) -g -O0 -fsanitize=address -o /tmp/_asan_test /tmp/_asan_test.c -ldl
	-/tmp/_asan_test || true
	@rm -f /tmp/_asan_test /tmp/_asan_test.c

clean:
	rm -f libdemo.dylib libdemo_asan.dylib poc_exploit harness_asan

.PHONY: all poc asan clean
