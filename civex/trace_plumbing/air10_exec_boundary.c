/*
 * air10_exec_boundary.c - Hardened C11 Process Execution Supervisor
 * =================================================================
 * Provides deterministic, isolated execution supervision:
 * - Fork/execv isolation with direct binary invocation (no shell injection)
 * - Wall-clock and CPU time measurement via clock_gettime and rusage
 * - Captures exit status, termination signals, memory usage (RSS)
 * - Streaming SHA-256 computation on process stdout
 * - Structured JSON output for audit DAG correlation
 */

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <strings.h>


/* Minimal Self-Contained SHA-256 implementation */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[64];
} SHA256_CTX;

#define DBL_INT_ADD(a,b,c) if ((a += c) < c) ++(b)
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->buffer[ctx->count % 64] = data[i];
        ctx->count++;
        if ((ctx->count % 64) == 0)
            sha256_transform(ctx, ctx->buffer);
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    size_t i = ctx->count % 64;
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0x00;
    }
    uint64_t total_bits = ctx->count * 8;
    for (int j = 7; j >= 0; j--) {
        ctx->buffer[56 + (7 - j)] = (total_bits >> (j * 8)) & 0xFF;
    }
    sha256_transform(ctx, ctx->buffer);
    for (i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            hash[j * 4 + i] = (ctx->state[j] >> (24 - i * 8)) & 0x000000ff;
        }
    }
}

static void hash_to_hex(const uint8_t hash[32], char hex_out[65]) {
    for (int i = 0; i < 32; i++) {
        sprintf(hex_out + (i * 2), "%02x", hash[i]);
    }
    hex_out[64] = '\0';
}


static double timespec_to_ms(struct timespec ts) {
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void terminate_and_reap_child(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    usleep(10000); /* 10ms grace period */
    int status;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <TRACE_ID> <PARENT_SPAN_ID> <BINARY_PATH> [ARGS...]\n", argv[0]);
        return 1;
    }

    const char *trace_id = argv[1];
    const char *parent_span_id = argv[2];
    const char *binary_path = argv[3];
    const char *input_file = getenv("AIR10_INPUT_FILE");
    if (!input_file || input_file[0] == '\0') {
        input_file = (argc > 4) ? argv[4] : "";
    }
    if (input_file[0] != '\0' && access(input_file, F_OK) != 0) {
        for (int i = 4; i < argc; i++) {
            if (access(argv[i], F_OK) == 0) {
                input_file = argv[i];
                break;
            }
        }
    }

    if (access(binary_path, X_OK) != 0) {
        fprintf(stderr, "ERROR: Binary '%s' not found or not executable\n", binary_path);
        return 126;
    }

    /* 1. Read binary bytes, compute authoritative C11 executed_binary_sha256 */
    char executed_binary_sha256[65] = {0};
    int bin_fd = open(binary_path, O_RDONLY);
    if (bin_fd < 0) {
        fprintf(stderr, "ERROR: Binary '%s' cannot be opened for reading: %s\n", binary_path, strerror(errno));
        return 126;
    }
    SHA256_CTX bin_ctx;
    sha256_init(&bin_ctx);
    uint8_t bin_buf[8192];
    ssize_t bin_n;

    /* Prepare content-addressed execution snapshot directory */
    const char *snap_dir = getenv("AIR10_EXEC_SNAPSHOT_DIR");
    if (!snap_dir || snap_dir[0] == '\0') {
        snap_dir = "/tmp/air10_exec_snapshots";
    }
    mkdir(snap_dir, 0700);

    size_t bin_cap = 65536;
    size_t bin_len = 0;
    uint8_t *bin_bytes = (uint8_t *)malloc(bin_cap);
    if (!bin_bytes) {
        close(bin_fd);
        return 71;
    }
    while ((bin_n = read(bin_fd, bin_buf, sizeof(bin_buf))) > 0) {
        sha256_update(&bin_ctx, bin_buf, (size_t)bin_n);
        while (bin_len + (size_t)bin_n > bin_cap) {
            bin_cap *= 2;
            uint8_t *new_bytes = (uint8_t *)realloc(bin_bytes, bin_cap);
            if (!new_bytes) {
                free(bin_bytes);
                close(bin_fd);
                return 71;
            }
            bin_bytes = new_bytes;
        }
        memcpy(bin_bytes + bin_len, bin_buf, (size_t)bin_n);
        bin_len += (size_t)bin_n;
    }
    close(bin_fd);
    if (bin_n < 0) {
        free(bin_bytes);
        return 71;
    }

    uint8_t bin_hash[32];
    sha256_final(&bin_ctx, bin_hash);
    hash_to_hex(bin_hash, executed_binary_sha256);

    /* Expected Binary SHA verification (Fail-Closed) */
    const char *expected_bin_sha = getenv("AIR10_EXPECTED_BINARY_SHA");
    const char *require_bin_sha = getenv("AIR10_REQUIRE_EXPECTED_SHA");
    if (require_bin_sha && (require_bin_sha[0] == '1' || strcasecmp(require_bin_sha, "true") == 0)) {
        if (!expected_bin_sha || expected_bin_sha[0] == '\0') {
            fprintf(stderr, "ERROR: MANDATORY_EXPECTED_BINARY_SHA_MISSING: AIR10_EXPECTED_BINARY_SHA required but not set\n");
            free(bin_bytes);
            return 76;
        }
    }
    if (expected_bin_sha && expected_bin_sha[0] != '\0') {
        if (strcasecmp(executed_binary_sha256, expected_bin_sha) != 0) {
            fprintf(stderr, "ERROR: BINARY_INTEGRITY_MISMATCH: executed SHA '%s' != expected SHA '%s'\n", executed_binary_sha256, expected_bin_sha);
            free(bin_bytes);
            return 76;
        }
    }

    /* Content-Addressed Execution Snapshot:
     * Write exact bytes read & verified to /tmp/air10_exec_snapshots/<sha256>
     * with permissions 0700. If snapshot already exists, verify its bytes and ownership (Anti-Poisoning).
     * Completely eliminates time-of-check-to-time-of-use (TOCTOU) and ABA mutation attacks.
     */
    char snapshot_path[512];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/%s", snap_dir, executed_binary_sha256);
    
    int snap_fd = open(snapshot_path, O_WRONLY | O_CREAT | O_EXCL, 0500);
    if (snap_fd >= 0) {
        size_t written_total = 0;
        int write_err = 0;
        while (written_total < bin_len) {
            ssize_t w = write(snap_fd, bin_bytes + written_total, bin_len - written_total);
            if (w < 0) {
                if (errno == EINTR) continue;
                write_err = 1;
                break;
            }
            written_total += (size_t)w;
        }
        if (write_err || written_total < bin_len) {
            unlink(snapshot_path);
            close(snap_fd);
            free(bin_bytes);
            fprintf(stderr, "ERROR: Failed to write snapshot completely\n");
            return 71;
        }
        if (fsync(snap_fd) != 0) {
            unlink(snapshot_path);
            close(snap_fd);
            free(bin_bytes);
            fprintf(stderr, "ERROR: Failed to fsync snapshot\n");
            return 71;
        }
        close(snap_fd);
        chmod(snapshot_path, 0500);
    } else if (errno == EEXIST) {
        /* Pre-existing snapshot: verify ownership, permissions, and re-hash all bytes (Anti-Poisoning) */
        int exist_fd = open(snapshot_path, O_RDONLY | O_NOFOLLOW);
        if (exist_fd < 0) {
            free(bin_bytes);
            fprintf(stderr, "ERROR: Cannot open existing snapshot for verification: %s\n", strerror(errno));
            return 79;
        }
        struct stat st;
        if (fstat(exist_fd, &st) != 0) {
            close(exist_fd);
            free(bin_bytes);
            return 79;
        }
        if (st.st_uid != getuid()) {
            close(exist_fd);
            free(bin_bytes);
            fprintf(stderr, "ERROR: SNAPSHOT_OWNERSHIP_MISMATCH: owner %d != current uid %d\n", (int)st.st_uid, (int)getuid());
            return 79;
        }
        if ((st.st_mode & 0777) != 0500 && (st.st_mode & 0777) != 0700) {
            close(exist_fd);
            free(bin_bytes);
            fprintf(stderr, "ERROR: SNAPSHOT_PERMISSIONS_MISMATCH: mode %o untrusted\n", (unsigned int)(st.st_mode & 0777));
            return 79;
        }
        char exist_sha[65] = {0};
        SHA256_CTX exist_ctx;
        sha256_init(&exist_ctx);
        uint8_t ebuf[8192];
        ssize_t en;
        while ((en = read(exist_fd, ebuf, sizeof(ebuf))) > 0) {
            sha256_update(&exist_ctx, ebuf, (size_t)en);
        }
        close(exist_fd);
        if (en < 0) {
            free(bin_bytes);
            return 79;
        }
        uint8_t e_hash[32];
        sha256_final(&exist_ctx, e_hash);
        hash_to_hex(e_hash, exist_sha);
        if (strcasecmp(exist_sha, executed_binary_sha256) != 0) {
            fprintf(stderr, "ERROR: SNAPSHOT_CACHE_POISONED: existing snapshot SHA '%s' != expected SHA '%s'\n", exist_sha, executed_binary_sha256);
            free(bin_bytes);
            return 79;
        }
    } else {
        free(bin_bytes);
        fprintf(stderr, "ERROR: Failed to create or access snapshot path '%s': %s\n", snapshot_path, strerror(errno));
        return 71;
    }
    free(bin_bytes);

    /* 2. If input file is specified and exists, compute authoritative C11 executed_input_sha256 and create immutable input snapshot */
    char executed_input_sha256[65] = {0};
    char input_snapshot_path[512] = {0};
    if (strlen(input_file) > 0 && access(input_file, F_OK) == 0) {
        int inp_fd = open(input_file, O_RDONLY);
        if (inp_fd < 0) {
            fprintf(stderr, "ERROR: Failed to open input file '%s'\n", input_file);
            return 72;
        }
        SHA256_CTX inp_ctx;
        sha256_init(&inp_ctx);
        size_t inp_cap = 65536;
        size_t inp_len = 0;
        uint8_t *inp_bytes = (uint8_t *)malloc(inp_cap);
        if (!inp_bytes) { close(inp_fd); return 71; }
        uint8_t ibuf[8192];
        ssize_t in_n;
        while ((in_n = read(inp_fd, ibuf, sizeof(ibuf))) > 0) {
            sha256_update(&inp_ctx, ibuf, (size_t)in_n);
            while (inp_len + (size_t)in_n > inp_cap) {
                inp_cap *= 2;
                uint8_t *nb = (uint8_t *)realloc(inp_bytes, inp_cap);
                if (!nb) { free(inp_bytes); close(inp_fd); return 71; }
                inp_bytes = nb;
            }
            memcpy(inp_bytes + inp_len, ibuf, (size_t)in_n);
            inp_len += (size_t)in_n;
        }
        close(inp_fd);
        if (in_n < 0) { free(inp_bytes); return 71; }
        uint8_t inp_hash[32];
        sha256_final(&inp_ctx, inp_hash);
        hash_to_hex(inp_hash, executed_input_sha256);

        const char *expected_inp_sha = getenv("AIR10_EXPECTED_INPUT_SHA");
        if (expected_inp_sha && expected_inp_sha[0] != '\0') {
            if (strcasecmp(executed_input_sha256, expected_inp_sha) != 0) {
                fprintf(stderr, "ERROR: INPUT_INTEGRITY_MISMATCH: input file SHA '%s' != expected '%s'\n", executed_input_sha256, expected_inp_sha);
                free(inp_bytes);
                return 77;
            }
        }

        /* Create immutable input snapshot in /tmp/air10_input_snapshots */
        const char *inp_snap_dir = getenv("AIR10_INPUT_SNAPSHOT_DIR");
        if (!inp_snap_dir || inp_snap_dir[0] == '\0') {
            inp_snap_dir = "/tmp/air10_input_snapshots";
        }
        mkdir(inp_snap_dir, 0700);
        snprintf(input_snapshot_path, sizeof(input_snapshot_path), "%s/in_%s", inp_snap_dir, executed_input_sha256);

        int in_snap_fd = open(input_snapshot_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (in_snap_fd >= 0) {
            size_t in_w_total = 0;
            int in_w_err = 0;
            while (in_w_total < inp_len) {
                ssize_t iw = write(in_snap_fd, inp_bytes + in_w_total, inp_len - in_w_total);
                if (iw < 0) {
                    if (errno == EINTR) continue;
                    in_w_err = 1;
                    break;
                }
                in_w_total += (size_t)iw;
            }
            if (in_w_err || in_w_total < inp_len) {
                unlink(input_snapshot_path);
                close(in_snap_fd);
                free(inp_bytes);
                return 71;
            }
            if (fsync(in_snap_fd) != 0) {
                unlink(input_snapshot_path);
                close(in_snap_fd);
                free(inp_bytes);
                fprintf(stderr, "ERROR: Failed to fsync input snapshot\n");
                return 71;
            }
            close(in_snap_fd);
            chmod(input_snapshot_path, 0600);
        } else if (errno == EEXIST) {
            int ex_in_fd = open(input_snapshot_path, O_RDONLY | O_NOFOLLOW);
            if (ex_in_fd < 0) {
                free(inp_bytes);
                return 79;
            }
            struct stat inst;
            if (fstat(ex_in_fd, &inst) != 0 || inst.st_uid != getuid() || ((inst.st_mode & 0777) != 0600 && (inst.st_mode & 0777) != 0400)) {
                close(ex_in_fd);
                free(inp_bytes);
                fprintf(stderr, "ERROR: INPUT_SNAPSHOT_SECURITY: untrusted ownership or permissions on existing input snapshot\n");
                return 79;
            }
            char ex_in_sha[65] = {0};
            SHA256_CTX ex_ictx;
            sha256_init(&ex_ictx);
            uint8_t ex_ibuf[8192];
            ssize_t ex_in;
            while ((ex_in = read(ex_in_fd, ex_ibuf, sizeof(ex_ibuf))) > 0) {
                sha256_update(&ex_ictx, ex_ibuf, (size_t)ex_in);
            }
            close(ex_in_fd);
            if (ex_in < 0) { free(inp_bytes); return 79; }
            uint8_t ex_ihash[32];
            sha256_final(&ex_ictx, ex_ihash);
            hash_to_hex(ex_ihash, ex_in_sha);
            if (strcasecmp(ex_in_sha, executed_input_sha256) != 0) {
                fprintf(stderr, "ERROR: INPUT_SNAPSHOT_POISONED: existing input snapshot SHA '%s' != expected '%s'\n", ex_in_sha, executed_input_sha256);
                free(inp_bytes);
                return 79;
            }
        }
        free(inp_bytes);
    }

    /* Optional stdout preservation path from environment */
    const char *capture_path = getenv("AIR10_STDOUT_CAPTURE_PATH");
    int capture_fd = -1;
    if (capture_path && capture_path[0] != '\0') {
        capture_fd = open(capture_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (capture_fd < 0) {
            fprintf(stderr, "ERROR: Could not open AIR10_STDOUT_CAPTURE_PATH '%s' for writing: %s\n", capture_path, strerror(errno));
            return 71;
        }
    }

    int pipe_out[2];
    if (pipe(pipe_out) != 0) {
        perror("pipe");
        if (capture_fd >= 0) close(capture_fd);
        return 1;
    }

    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        if (capture_fd >= 0) close(capture_fd);
        return 1;
    }

    if (pid == 0) {
        /* Child Process */
        close(pipe_out[0]);
        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_out[1]);
        if (capture_fd >= 0) close(capture_fd);

        /* Set environment */
        setenv("AIR10_TRACE_ID", trace_id, 1);
        setenv("AIR10_PARENT_SPAN_ID", parent_span_id, 1);

        /* Build arbitrary argv: child_args[0] = snapshot_path, child_args[1..] = argv[4..], NULL */
        int child_argc = argc - 3;
        char **child_args = (char **)malloc(sizeof(char *) * (child_argc + 1));
        if (!child_args) {
            perror("malloc");
            _exit(127);
        }
        child_args[0] = (char *)snapshot_path;
        for (int i = 4; i < argc; i++) {
            child_args[i - 3] = argv[i];
        }
        child_argc = argc - 3;
        child_args[child_argc] = NULL;

        /* Rewrite any argument matching original input_file to immutable input_snapshot_path */
        if (input_snapshot_path[0] != '\0') {
            for (int i = 1; i < child_argc; i++) {
                if (child_args[i] && strcmp(child_args[i], input_file) == 0) {
                    child_args[i] = input_snapshot_path;
                }
            }
            setenv("AIR10_INPUT_FILE", input_snapshot_path, 1);
        }

        /* If system binary in read-only SIP path on macOS, execute directly */
        int is_sys_bin = 0;
#ifdef __APPLE__
        if (strncmp(binary_path, "/bin/", 5) == 0 ||
            strncmp(binary_path, "/usr/bin/", 9) == 0 ||
            strncmp(binary_path, "/sbin/", 6) == 0 ||
            strncmp(binary_path, "/usr/sbin/", 10) == 0) {
            is_sys_bin = 1;
        }
#endif
        if (is_sys_bin) {
            child_args[0] = (char *)binary_path;
            execv(binary_path, child_args);
        } else {
            child_args[0] = (char *)snapshot_path;
            execv(snapshot_path, child_args);
        }

        /* FAIL CLOSED: Zero fallback to mutable binary_path */
        perror("execv");
        _exit(78);
    }

    /* Parent Process: Supervisor */
    close(pipe_out[1]);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    uint8_t buffer[8192];
    ssize_t bytes_read;
    size_t total_stdout_bytes = 0;
    int read_error = 0;

    while (1) {
        bytes_read = read(pipe_out[0], buffer, sizeof(buffer));
        if (bytes_read < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "ERROR: Read from supervisor pipe failed: %s\n", strerror(errno));
            read_error = 1;
            break;
        }
        if (bytes_read == 0) {
            break; /* EOF */
        }
        sha256_update(&ctx, buffer, (size_t)bytes_read);
        total_stdout_bytes += (size_t)bytes_read;
        if (capture_fd >= 0) {
            size_t written_total = 0;
            while (written_total < (size_t)bytes_read) {
                ssize_t w = write(capture_fd, buffer + written_total, (size_t)bytes_read - written_total);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    fprintf(stderr, "ERROR: Write to capture file '%s' failed: %s\n", capture_path, strerror(errno));
                    close(pipe_out[0]);
                    close(capture_fd);
                    terminate_and_reap_child(pid);
                    return 74;
                }
                written_total += (size_t)w;
            }
        }
    }
    close(pipe_out[0]);

    if (read_error) {
        if (capture_fd >= 0) close(capture_fd);
        terminate_and_reap_child(pid);
        return 75;
    }

    if (capture_fd >= 0) {
        if (fsync(capture_fd) != 0) {
            fprintf(stderr, "ERROR: fsync on capture file '%s' failed: %s\n", capture_path, strerror(errno));
            close(capture_fd);
            terminate_and_reap_child(pid);
            return 74;
        }
        close(capture_fd);
    }

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    char stdout_sha256[65];
    hash_to_hex(hash, stdout_sha256);

    int status = 0;
    struct rusage usage;
    wait4(pid, &status, 0, &usage);

    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    double wall_duration_ms = timespec_to_ms(end_ts) - timespec_to_ms(start_ts);
    double utime_ms = (double)usage.ru_utime.tv_sec * 1000.0 + (double)usage.ru_utime.tv_usec / 1000.0;
    double stime_ms = (double)usage.ru_stime.tv_sec * 1000.0 + (double)usage.ru_stime.tv_usec / 1000.0;
    long max_rss = usage.ru_maxrss;
#ifdef __APPLE__
    max_rss = max_rss / 1024; /* Apple returns bytes, convert to KB */
#endif

    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1);

    /* Emit deterministic machine verification JSON */
    printf("{\n");
    printf("  \"trace_id\": \"%s\",\n", trace_id);
    printf("  \"parent_span_id\": \"%s\",\n", parent_span_id);
    printf("  \"binary_path\": \"%s\",\n", binary_path);
    printf("  \"executed_binary_sha256\": \"%s\",\n", executed_binary_sha256);
    printf("  \"input_file\": \"%s\",\n", input_file);
    printf("  \"executed_input_sha256\": \"%s\",\n", executed_input_sha256[0] ? executed_input_sha256 : "NO_INPUT_FILE");
    printf("  \"exit_code\": %d,\n", exit_code);
    printf("  \"wall_duration_ms\": %.3f,\n", wall_duration_ms);
    printf("  \"utime_ms\": %.3f,\n", utime_ms);
    printf("  \"stime_ms\": %.3f,\n", stime_ms);
    printf("  \"max_rss_kb\": %ld,\n", max_rss);
    printf("  \"stdout_bytes\": %zu,\n", total_stdout_bytes);
    printf("  \"stdout_sha256\": \"%s\",\n", stdout_sha256);
    printf("  \"stdout_capture_path\": \"%s\",\n", capture_path ? capture_path : "");
    printf("  \"supervisor\": \"air10_exec_boundary_c11\"\n");
    printf("}\n");

    return exit_code;
}
