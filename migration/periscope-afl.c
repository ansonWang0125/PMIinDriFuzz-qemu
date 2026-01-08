/*
 * periscope-afl.c
 *
 * Authors:
 *  dokyungs@uci.edu
 */

#include "qemu/osdep.h"
#include "qapi/error.h"

#include <sys/shm.h>

#include "periscope.h"
#include "periscope-timers.h"

#include "libafl.h"

#define AFL_COVERAGE_SUPPORT 1

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1 << MAP_SIZE_POW2)

static int st_pipe;
static int ctl_pipe;
static char *shm_ptr;
static int shm_id;

static char *afl_out_file = NULL;
static char *afl_out_dir = NULL;
static char afl_queue_file[512];
static char *afl_cur_input = NULL;
static int afl_cur_input_fd = -1;
static int afl_cur_input_size = -1;

static char *afl_get_cur_input(uint32_t *len) {
    if (len) {
        *len = afl_cur_input_size;

        if (*len > MAX_INPUT_BYTES)
            *len = MAX_INPUT_BYTES;
    }

    return afl_cur_input;
}

static char *afl_fetch_cur_input(uint32_t* len) {
    int res;
    int prev_timed_out;
    int child_pid = 1; // fake child_pid

    FuzzerState *s = fuzzer_get_current();
    if (!s) {
        printf("periscope: fuzzer not initialized!!!\n");
        return NULL;
    }

    if ((res = read(ctl_pipe, &prev_timed_out, 4)) != 4) {
        printf("periscope: read from control pipe failed\n");
        return NULL;
    }

    if (prev_timed_out > 0) {
        printf("periscope: AFL reports timeout\n");
    }

    if ((res = write(st_pipe, &child_pid, 4)) != 4) {
        printf("periscope: write to status pipe failed\n");
        return NULL;
    }

    // printf("periscope: fetching input...\n");

    if (afl_cur_input) {
        munmap(afl_cur_input, afl_cur_input_size);
        afl_cur_input = NULL;
    }

    if (afl_cur_input_fd > 0) {
        qemu_close(afl_cur_input_fd);
    }

    afl_cur_input_fd = qemu_open(afl_out_file, O_RDONLY|O_BINARY);
    if (afl_cur_input_fd < 0) {
        printf("periscope: afl cur input does not exist!!!\n");
        exit(1);
    }

    struct stat st;
    stat(afl_out_file, &st);
    afl_cur_input_size = st.st_size;

    afl_cur_input = mmap(NULL, afl_cur_input_size, PROT_READ,
                         MAP_PRIVATE | MAP_POPULATE,
                         afl_cur_input_fd, 0);

    int mutated_at = -1;
    int afl_cur_queue_fd = qemu_open(afl_queue_file, O_RDONLY | O_BINARY);
    if (afl_cur_queue_fd > 0) {
        stat(afl_queue_file, &st);
        int afl_queue_input_size = st.st_size;

        char *afl_queue_input =
            mmap(NULL, afl_queue_input_size, PROT_READ,
                 MAP_PRIVATE | MAP_POPULATE, afl_cur_queue_fd, 0);

        if (afl_queue_input == NULL) {
            printf("periscope: afl queue input mmap failed\n");
        }

        int smaller = afl_queue_input_size;
        if (smaller > afl_cur_input_size) {
            smaller = afl_cur_input_size;
        }

        mutated_at = 0;
        for (int i = 0; i < smaller; i++) {
            mutated_at = i;
            if (afl_cur_input[i] != afl_queue_input[i]) {
                break;
            }
        }

        munmap(afl_queue_input, afl_queue_input_size);
        close(afl_cur_queue_fd);
    }

    printf("periscope: afl mutated input at %d\n", mutated_at);

    if (mutated_at > 0) {
        periscope_change_chkpt_policy(
            PERISCOPE_CHKPT_TIME_ONLY_DISABLED_AFTER_NTH, mutated_at - 1);
    } else if (mutated_at == -1) {
        periscope_change_chkpt_policy(PERISCOPE_CHKPT_TIME_ONLY, -1);
    } else {
        periscope_change_chkpt_policy(PERISCOPE_CHKPT_DISABLED, -1);
    }

#if !AFL_COVERAGE_SUPPORT
    int status = 0;
    if ((res = write(st_pipe, &status, 4)) != 4) {
        printf("periscope: write to status pipe failed\n");
    }
#endif

    return afl_get_cur_input(len);
}

static int afl_fuzzer_mmio_read(unsigned size, uint64_t *out) {
    if (afl_cur_input == NULL) {
        printf("periscope: input not found!!!\n");
        return -1;
    }

    FuzzerState *s = fuzzer_get_current();
    assert(s != NULL);

    periscope_input_desc *cur = s->cur_input;
    assert(cur != NULL);

    *out = 0;

    switch (size) {
    case 1:
        if (cur->used_len + size <= afl_cur_input_size) {
            *out = *((uint8_t*)&afl_cur_input[cur->used_len]);
            cur->used_len += size;
        }
        break;
    case 2:
        if (cur->used_len + size <= afl_cur_input_size) {
            *out = *((uint16_t*)&afl_cur_input[cur->used_len]);
            cur->used_len += size;
        }
        break;
    case 4:
        if (cur->used_len + size <= afl_cur_input_size) {
            *out = *((uint32_t*)&afl_cur_input[cur->used_len]);
            cur->used_len += size;
        }
        break;
    case 8:
        if (cur->used_len + sizeof(uint64_t) <= afl_cur_input_size) {
            *out = *((uint64_t*)&afl_cur_input[cur->used_len]);
            cur->used_len += sizeof(uint64_t);
        }
        break;
    default:
        printf("periscope: unexpected size!\n");
        if (cur->used_len + sizeof(uint64_t) <= afl_cur_input_size) {
            *out = *((uint64_t*)&afl_cur_input[cur->used_len]);
            cur->used_len += sizeof(uint64_t);
        }
        break;
    }

    return 0;
}

#if AFL_COVERAGE_SUPPORT
static void afl_cur_input_executed(uint8_t *trace_bits, uint32_t used_len, uint64_t elapsed_ms, bool timed_out) {
    int res;
    int status = 0;

    FuzzerState *fs = fuzzer_get_current();
    assert(fs);
    assert(fs->cur_cp);
    qemu_timeval elapsed;
    elapsed.tv_sec = (elapsed_ms) / 1000;
    elapsed.tv_usec = ((elapsed_ms) % 1000) * 1000;
    memcpy(&fs->cur_cp->exec_time, &elapsed, sizeof(qemu_timeval));

    printf("periscope: stat=[");
    for (int stat = 0; stat < stat_count; stat++) {
        if (stat > 0)
            printf(",");
        if (stat == stat_killed) {
            printf("%d", timed_out ? 1 : 0);
            continue;
        }
        uint32_t v = periscope_get_stat(stat);
        printf("%d", v);
    }
    char timestr[sizeof "2011-10-08T07:07:09Z"];
    time_t now;
    time(&now);
    strftime(timestr, sizeof(timestr), "%FT%TZ", gmtime(&now));
    printf("] @ %s\n", timestr);

    // printf("periscope: feedback %p\n", trace_bits);

    if (shm_ptr && trace_bits == NULL) {
        printf("periscope: no feedback provided!\n");
        goto signal_afl;
    }

    if (shm_ptr == NULL) { // dumb mode?
        goto signal_afl;
    }

    memcpy(shm_ptr, trace_bits, MAP_SIZE);

signal_afl:
#if 0
    if (timed_out) {
        status = 9; // Give AFL a signal that this input causes timeout.
        // printf("periscope: timeout\n");
    }
#endif

    if ((res = write(st_pipe, &status, 4)) != 4) {
        printf("periscope: write to status pipe failed\n");
    }

    if ((res = write(st_pipe, &used_len, 4)) != 4) {
        printf("periscope: write to status pipe failed\n");
    }
}
#endif

void start_afl_fuzzer(const char *uri, int in_st_pipe, int in_ctl_pipe, int in_shm_id, Error **errp) {
    printf("periscope: initializing AFL io channels\n");

    if (uri == NULL) {
        st_pipe = in_st_pipe;
        ctl_pipe = in_ctl_pipe;
        shm_id = in_shm_id;
    }
    else {
        char tmp[1024];
        strncpy(tmp, uri, sizeof(tmp));

        st_pipe = strtol(strtok(tmp, ","), NULL, 0);
        ctl_pipe = strtol(strtok(NULL, ","), NULL, 0);

        shm_id = -1;
        char *shm_str = strtok(NULL, ",");
        if (shm_str) {
            shm_id = strtol(shm_str, NULL, 0);
        }
    }

    if (st_pipe == -1 || ctl_pipe == -1)
        return;

    shm_ptr = NULL;
    if (shm_id > -1) {
        shm_ptr = shmat(shm_id, NULL, 0);
        if (shm_ptr) {
            printf("periscope: AFL shm (id=%d, ptr=%p) initialized\n", shm_id, shm_ptr);
        }
    }

    afl_out_file = getenv("__PERISCOPE_OUT_FILE");
    afl_out_dir = getenv("__PERISCOPE_OUT_DIR");
    strcpy(afl_queue_file, afl_out_dir);
    char *master_id = getenv("__PERISCOPE_MASTER_ID");
    if (master_id) {
        strcat(afl_queue_file, "/");
        strcat(afl_queue_file, master_id);
    } else {
        char *secondary_id = getenv("__PERISCOPE_SECONDARY_ID");
        if (secondary_id) {
            strcat(afl_queue_file, "/");
            strcat(afl_queue_file, secondary_id);
        }
    }
    strcat(afl_queue_file, "/queue_cur");
    printf("periscope: queue_cur at '%s'\n", afl_queue_file);

    FuzzerState *s = fuzzer_get_current();
    assert(s != NULL);

    s->mode = PERISCOPE_MODE_AFL;
    s->mmio_read = afl_fuzzer_mmio_read;
    s->fetch_next = afl_fetch_cur_input;
    s->get_cur = afl_get_cur_input;
#if AFL_COVERAGE_SUPPORT
    s->cur_executed = afl_cur_input_executed;
#endif

#ifdef CONFIG_PERISCOPE
    s->get_queue_cur_info = libafl_get_queue_cur_info;
#endif

    printf("periscope: AFL io channels (st=%d, ctl=%d) initialized\n",
            st_pipe, ctl_pipe);
}
