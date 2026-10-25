/*
 * SO Audit Demo — Demonstrates 5 vulnerability patterns in a native library
 *
 * Models the workflow of auditing an Android .so or Linux shared library:
 *   1. Load the library via dlopen (simulating pulling from APK)
 *   2. Enumerate and test exported functions
 *   3. Trigger each vulnerability class with crafted input
 *
 * Each test runs in a forked child for crash isolation.
 *
 * Compile:
 *   clang -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 \
 *         -o audit_demo audit_demo.c -ldl
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/wait.h>

/* Function pointer types matching the library exports */
typedef int (*parse_config_fn)(const char *, int);
typedef int (*process_image_fn)(const uint8_t *, int);
typedef int (*log_event_fn)(const char *, int);
typedef int (*decrypt_blob_fn)(const uint8_t *, int, uint8_t *, int);
typedef int (*exec_cmd_fn)(const char *, const char *);
typedef float (*read_sensor_fn)(const void *);
typedef const char *(*get_version_fn)(void);

static int run_test(const char *name, void (*test_fn)(void *), void *ctx) {
    printf("[*] Testing: %s\n", name);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        test_fn(ctx);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) {
            printf("    Result: exited normally (code %d)\n", code);
        } else {
            printf("    Result: exited with code %d\n", code);
        }
        return code;
    }
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        printf("    Result: CRASHED (signal %d — %s)\n", sig,
               sig == 11 ? "SIGSEGV" : sig == 6 ? "SIGABRT" :
               sig == 10 ? "SIGBUS" : "other");
        return -sig;
    }
    return -999;
}

/* ================================================================
 * Test contexts (hold function pointers and test data)
 * ================================================================ */
typedef struct {
    parse_config_fn fn;
} config_ctx_t;

typedef struct {
    process_image_fn fn;
} image_ctx_t;

typedef struct {
    log_event_fn fn;
} log_ctx_t;

typedef struct {
    decrypt_blob_fn fn;
} decrypt_ctx_t;

typedef struct {
    exec_cmd_fn fn;
} cmd_ctx_t;

/* ================================================================
 * VULN 1: Stack overflow via sscanf
 * ================================================================ */
static void test_config_safe(void *ctx) {
    config_ctx_t *c = (config_ctx_t *)ctx;
    const char *config = "name = hello\nport = 8080\n";
    int r = c->fn(config, strlen(config));
    printf("    Parsed %d entries (safe input)\n", r);
}

static void test_config_overflow(void *ctx) {
    config_ctx_t *c = (config_ctx_t *)ctx;
    /* Create a key longer than 64 bytes to overflow key[64] */
    char payload[512];
    memset(payload, 'A', 200);
    memcpy(payload + 200, " = value\n", 9);
    payload[209] = '\0';
    printf("    Sending 200-byte key into key[64] buffer...\n");
    c->fn(payload, strlen(payload));
}

/* ================================================================
 * VULN 2: Integer overflow → heap overflow
 * ================================================================ */
static void test_image_safe(void *ctx) {
    image_ctx_t *c = (image_ctx_t *)ctx;
    /* 4x4 RGB image = 48 pixels, well within bounds */
    uint8_t data[60];
    memset(data, 0, sizeof(data));
    /* Magic: "BITG" = 0x42495447 little-endian */
    data[0] = 0x47; data[1] = 0x54; data[2] = 0x49; data[3] = 0x42;
    /* width=4, height=4, channels=3 */
    data[4] = 4; data[5] = 0;
    data[6] = 4; data[7] = 0;
    data[8] = 3;
    /* Fill pixel data */
    for (int i = 12; i < 60; i++) data[i] = (uint8_t)(i * 7);
    int r = c->fn(data, sizeof(data));
    printf("    Processed image, result=%d (safe input)\n", r);
}

static void test_image_intoverflow(void *ctx) {
    image_ctx_t *c = (image_ctx_t *)ctx;
    /* width=65535, height=65535, channels=4
     * 65535 * 65535 * 4 = 17,179,607,044 → overflows uint32 to small value
     * malloc allocates small buffer, memcpy writes much more */
    uint8_t data[1024];
    memset(data, 0x42, sizeof(data));
    /* Magic */
    data[0] = 0x47; data[1] = 0x54; data[2] = 0x49; data[3] = 0x42;
    /* width=65535 (0xFFFF), height=65535 */
    data[4] = 0xFF; data[5] = 0xFF;
    data[6] = 0xFF; data[7] = 0xFF;
    /* channels=4 */
    data[8] = 4;
    printf("    Sending 65535x65535x4 image header (integer overflow)...\n");
    c->fn(data, sizeof(data));
}

/* ================================================================
 * VULN 3: Format string
 * ================================================================ */
static void test_log_safe(void *ctx) {
    log_ctx_t *c = (log_ctx_t *)ctx;
    int r = c->fn("user_login event_code=%d", 42);
    printf("    Logged %d bytes (safe input)\n", r);
}

static void test_log_fmtstr(void *ctx) {
    log_ctx_t *c = (log_ctx_t *)ctx;
    /* %x reads stack values, %n writes to memory */
    printf("    Sending format string payload: %%x.%%x.%%x.%%x.%%x.%%n\n");
    c->fn("%x.%x.%x.%x.%x.%x.%x.%x.%n", 0);
}

/* ================================================================
 * VULN 4: Use-after-free
 * ================================================================ */
static void test_decrypt_safe(void *ctx) {
    decrypt_ctx_t *c = (decrypt_ctx_t *)ctx;
    /* Construct valid encrypted blob: key_bytes + "DECK" XOR'd + body */
    uint8_t key_hdr[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t xor_key = 0x11 ^ 0x22 ^ 0x33 ^ 0x44;
    uint8_t body[] = "DECK" "Hello, decrypted world!";
    int body_len = strlen("DECK") + strlen("Hello, decrypted world!");
    uint8_t enc[128];
    memcpy(enc, key_hdr, 4);
    for (int i = 0; i < body_len; i++) enc[4 + i] = body[i] ^ xor_key;

    uint8_t output[128];
    int r = c->fn(enc, 4 + body_len, output, sizeof(output));
    if (r > 0) {
        output[r] = '\0';
        printf("    Decrypted: \"%s\" (%d bytes)\n", output, r);
    }
}

static void test_decrypt_uaf(void *ctx) {
    decrypt_ctx_t *c = (decrypt_ctx_t *)ctx;
    /* Invalid blob — decryption check fails, triggers UAF on error path */
    uint8_t enc[64];
    memset(enc, 0xAA, sizeof(enc));
    uint8_t output[128];
    printf("    Sending invalid blob to trigger UAF on error path...\n");
    int r = c->fn(enc, sizeof(enc), output, sizeof(output));
    printf("    Returned: %d (negative = error code from freed memory)\n", r);
}

/* ================================================================
 * VULN 5: Command injection
 * ================================================================ */
static void test_cmd_safe(void *ctx) {
    cmd_ctx_t *c = (cmd_ctx_t *)ctx;
    int r = c->fn("device001", "status");
    printf("    Command length: %d (safe input)\n", r);
}

static void test_cmd_injection(void *ctx) {
    cmd_ctx_t *c = (cmd_ctx_t *)ctx;
    printf("    Injecting: device_id=\"; cat /etc/passwd #\"\n");
    int r = c->fn("; cat /etc/passwd #", "status");
    printf("    Command length: %d (if system() were called, injection succeeds)\n", r);
}

int main(int argc, char **argv) {
    printf("========================================================\n");
    printf("  SO Audit Demo — Android/Linux Native Library Auditing\n");
    printf("========================================================\n\n");

    /* Detect library extension */
#ifdef __APPLE__
    const char *lib_path = "./libnative_parser.dylib";
#else
    const char *lib_path = "./libnative_parser.so";
#endif

    void *lib = dlopen(lib_path, RTLD_LAZY);
    if (!lib) {
        fprintf(stderr, "dlopen(%s): %s\n", lib_path, dlerror());
        return 1;
    }

    /* Resolve all exports */
    parse_config_fn  fn_config  = dlsym(lib, "native_parse_config");
    process_image_fn fn_image   = dlsym(lib, "native_process_image");
    log_event_fn     fn_log     = dlsym(lib, "native_log_event");
    decrypt_blob_fn  fn_decrypt = dlsym(lib, "native_decrypt_blob");
    exec_cmd_fn      fn_cmd     = dlsym(lib, "native_exec_cmd");
    read_sensor_fn   fn_sensor  = dlsym(lib, "native_read_sensor");
    get_version_fn   fn_ver     = dlsym(lib, "native_get_version");

    printf("Library: %s\n", lib_path);
    if (fn_ver) printf("Version: %s\n", fn_ver());
    printf("\nExported functions resolved:\n");
    printf("  native_parse_config  @ %p\n", (void *)fn_config);
    printf("  native_process_image @ %p\n", (void *)fn_image);
    printf("  native_log_event     @ %p\n", (void *)fn_log);
    printf("  native_decrypt_blob  @ %p\n", (void *)fn_decrypt);
    printf("  native_exec_cmd      @ %p\n", (void *)fn_cmd);
    printf("  native_read_sensor   @ %p\n", (void *)fn_sensor);
    printf("\n");

    int vulns_found = 0;

    /* ============================================================
     * VULN 1: Stack overflow (sscanf)
     * ============================================================ */
    printf("─────────────────────────────────────────────────────\n");
    printf("VULN 1: Stack Buffer Overflow (native_parse_config)\n");
    printf("  Pattern: sscanf(line, \"%%s = %%127s\", key[64], value)\n");
    printf("  Risk:    key has no size limit → overflow key[64]\n");
    printf("─────────────────────────────────────────────────────\n");
    {
        config_ctx_t ctx = { fn_config };
        run_test("Safe config input", test_config_safe, &ctx);
        int r = run_test("200-byte key overflow", test_config_overflow, &ctx);
        if (r < 0) vulns_found++;
    }
    printf("\n");

    /* ============================================================
     * VULN 2: Integer overflow → heap overflow
     * ============================================================ */
    printf("─────────────────────────────────────────────────────\n");
    printf("VULN 2: Integer Overflow → Heap Overflow (native_process_image)\n");
    printf("  Pattern: uint32 pixel_bytes = width * height * channels\n");
    printf("  Risk:    65535*65535*4 wraps uint32 → small malloc → big memcpy\n");
    printf("─────────────────────────────────────────────────────\n");
    {
        image_ctx_t ctx = { fn_image };
        run_test("Safe 4x4 RGB image", test_image_safe, &ctx);
        int r = run_test("65535x65535x4 integer overflow", test_image_intoverflow, &ctx);
        if (r < 0) vulns_found++;
    }
    printf("\n");

    /* ============================================================
     * VULN 3: Format string
     * ============================================================ */
    printf("─────────────────────────────────────────────────────\n");
    printf("VULN 3: Format String (native_log_event)\n");
    printf("  Pattern: snprintf(buf, sz, event_name, event_code)\n");
    printf("  Risk:    event_name IS the format string → %%x leaks, %%n writes\n");
    printf("─────────────────────────────────────────────────────\n");
    {
        log_ctx_t ctx = { fn_log };
        run_test("Safe log message", test_log_safe, &ctx);
        int r = run_test("Format string %%x...%%n", test_log_fmtstr, &ctx);
        if (r < 0) vulns_found++;
    }
    printf("\n");

    /* ============================================================
     * VULN 4: Use-after-free
     * ============================================================ */
    printf("─────────────────────────────────────────────────────\n");
    printf("VULN 4: Use-After-Free (native_decrypt_blob)\n");
    printf("  Pattern: free(temp); ... err = *(uint32_t*)(temp+4)\n");
    printf("  Risk:    reads freed heap memory → info leak or crash\n");
    printf("─────────────────────────────────────────────────────\n");
    {
        decrypt_ctx_t ctx = { fn_decrypt };
        run_test("Valid encrypted blob", test_decrypt_safe, &ctx);
        int r = run_test("Invalid blob (trigger UAF)", test_decrypt_uaf, &ctx);
        if (r < 0) vulns_found++;
        else printf("    ⚠ UAF didn't crash (common without ASan) — still a bug!\n");
    }
    printf("\n");

    /* ============================================================
     * VULN 5: Command injection
     * ============================================================ */
    printf("─────────────────────────────────────────────────────\n");
    printf("VULN 5: Command Injection (native_exec_cmd)\n");
    printf("  Pattern: snprintf(cmd, ..., \"... --id %%s ...\", device_id)\n");
    printf("  Risk:    no sanitization → shell metachar injection\n");
    printf("─────────────────────────────────────────────────────\n");
    {
        cmd_ctx_t ctx = { fn_cmd };
        run_test("Safe device ID", test_cmd_safe, &ctx);
        run_test("Injection: \"; cat /etc/passwd #\"", test_cmd_injection, &ctx);
        vulns_found++; /* Logic bug, doesn't crash */
    }
    printf("\n");

    /* ============================================================
     * Summary
     * ============================================================ */
    printf("========================================================\n");
    printf("  AUDIT SUMMARY\n");
    printf("========================================================\n");
    printf("\n");
    printf("  Library:     %s\n", lib_path);
    printf("  Functions:   7 exported, 5 with vulnerabilities\n");
    printf("  Crashes:     %d triggered in this run\n", vulns_found);
    printf("\n");
    printf("  ┌────┬──────────────────────┬──────────────────────────┬──────────┐\n");
    printf("  │ #  │ Function             │ Vulnerability            │ Severity │\n");
    printf("  ├────┼──────────────────────┼──────────────────────────┼──────────┤\n");
    printf("  │ 1  │ native_parse_config  │ Stack overflow (sscanf)  │ CRITICAL │\n");
    printf("  │ 2  │ native_process_image │ Integer→heap overflow    │ CRITICAL │\n");
    printf("  │ 3  │ native_log_event     │ Format string            │ HIGH     │\n");
    printf("  │ 4  │ native_decrypt_blob  │ Use-after-free           │ HIGH     │\n");
    printf("  │ 5  │ native_exec_cmd      │ Command injection        │ CRITICAL │\n");
    printf("  │ 6  │ native_read_sensor   │ (safe — control)         │ NONE     │\n");
    printf("  │ 7  │ native_get_version   │ (safe — trivial)         │ NONE     │\n");
    printf("  └────┴──────────────────────┴──────────────────────────┴──────────┘\n");
    printf("\n");
    printf("  FuzzGen4Ghidra Workflow:\n");
    printf("    1. Load this .so/.dylib in Ghidra\n");
    printf("    2. Run 'Scan Fuzz Targets' → see scoring for each function\n");
    printf("    3. Right-click high-score functions → 'Generate Fuzz Harness'\n");
    printf("    4. Compile harness with ASan → fuzz → find these bugs\n");
    printf("\n");
    printf("  To verify with ASan:\n");
    printf("    make asan   # rebuilds with -fsanitize=address\n");
    printf("                # ASan catches heap overflow and UAF that didn't crash above\n");

    dlclose(lib);
    return 0;
}
