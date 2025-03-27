#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <assert.h>
#include <stdlib.h>
#include <malloc.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <elf.h>

#include <stdint.h>
#include <stdbool.h>

volatile sig_atomic_t consecutive_sigsegv = 0;

#define SIGSEGV_THRESHOLD 10
#define BITMAP_MODE_FILE 1 // Store by file number
#define BITMAP_MODE_RANGE 2 // Store by interval

#define PAGE_SIZE 4096
#define MY_SIGSTKSZ 8192
void *insn_page;
volatile sig_atomic_t last_insn_signum = 0;
volatile sig_atomic_t executing_insn = 0;
uint32_t insn_offset = 0;
uint32_t mask = 0x1111;

static uint8_t sig_stack_array[MY_SIGSTKSZ];
stack_t sig_stack = {
    .ss_size = MY_SIGSTKSZ,
    .ss_sp = sig_stack_array,
};

void signal_handler(int, siginfo_t*, void*);
void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int);
void execution_boilerplate(void);
int init_insn_page(void);
void execute_insn_page(uint8_t*, size_t);
size_t fill_insn_buffer(uint8_t*, size_t, uint32_t);
uint64_t get_nano_timestamp(void);

extern char boilerplate_start, boilerplate_end, insn_location;

uint8_t * result_bitmap = NULL;
uint32_t bitmap_size = 0;
uint32_t range_start = 0;
uint32_t range_end = 0;
int file_number = -1;

uint32_t hidden_insn;
uint32_t cnt = 0;
uint32_t sigsegv_cnt = 0;
uint32_t sigill_cnt = 0;
uint32_t sigtrap_cnt = 0;
uint32_t sigbus_cnt = 0;
uint32_t no_signal = 0;
uint32_t instructions_checked = 0; // total udf insns

int init_bitmap(uint32_t start, uint32_t end) {
    range_start= start;
    range_end = end;

    uint32_t bits_needed = end - start;
    bitmap_size = (bits_needed + 7) / 8; // round up to bytes

    // allocate
    result_bitmap = (uint8_t *)calloc(bitmap_size, 1);
    if(!result_bitmap) {
        perror("calloc result bitmap failed");
        return 1;
    }

    char *file_num_env = getenv("RESULT_FILE_NUMBER"); // passed by argv
    if(file_num_env != NULL) {
        file_number = atoi(file_num_env);
    }

    return 0;
}

void mark_executable(uint32_t insn) {
    //offset
    uint32_t offset = insn - range_start;

    if(offset >= (bitmap_size * 8)) {
        return ; // exceed bit map range
    }

    uint32_t byte_index = offset / 8;
    uint8_t bit_position = offset % 8;

    result_bitmap[byte_index] |= (1 << bit_position);
}

void save_bitmap_results(void) {
    if(!result_bitmap) return;

    mkdir("bitmap_results", 0755);

    char filename[256];

    if(file_number >= 0) {
        // store by file number
        snprintf(filename, sizeof(filename), "bitmap_results/ranges_file_%d.txt", file_number);


        FILE *f = fopen(filename, "a");
        if(!f) {
            fprintf(stderr, "cannot open range file %s\n", filename);
            return;
        }

        // Lock
        flock(fileno(f), LOCK_EX);

        bool in_range = false;
        uint32_t range_start_val = 0;

        // traversing the bitmap
        for(uint32_t i = 0 ; i < bitmap_size * 8 ; ++i) {
            uint32_t insn = range_start + i;
            if(insn >= range_end) break;

            uint32_t byte_index = i / 8;
            uint8_t bit_position = i % 8;
            bool is_exec = (result_bitmap[byte_index] & (1 << bit_position)) != 0;

            if(is_exec && !in_range) {
                range_start_val = insn;
                in_range = true;
            } else if (!is_exec && in_range) {
                fprintf(f, "[%u, %u]\n", range_start_val, insn);
                in_range = false;
            }
        }

        if(in_range) {
            fprintf(f, "[%u, %u]\n", range_start_val, range_end);
        }

        flock(fileno(f), LOCK_UN);
        fclose(f);

        printf("executable instruction append to %s\n", filename);

    } else {
        // no filenumber, use interval to store
        snprintf(filename, sizeof(filename), "bitmap_results/bitmap_%u_%u.bin", range_start, range_end);

        FILE *f = fopen(filename, "wb");
        if(!f) {
            fprintf(stderr, "cannot create bitmap result by interval %s [%u, %u]\n", filename, range_start, range_end);
            return ;
        }

        // header
        fwrite(&range_start, sizeof(uint32_t), 1, f);
        fwrite(&range_end, sizeof(uint32_t), 1, f);

        // bitmap result
        fwrite(result_bitmap, 1, bitmap_size, f);

        fclose(f);
        printf("bitmap result store in %s\n", filename);
    }

    if (result_bitmap) {
        free(result_bitmap);
        result_bitmap = NULL;
    }

    printf("bitmap process done: interval[%u, %u], total %u executable instruction\n", range_start, range_end, no_signal);
}


void signal_handler(int sig_num, siginfo_t *sig_info, void *uc_ptr)
{
    // Suppress unused warning
    (void)sig_info;

    ucontext_t* uc = (ucontext_t*) uc_ptr;

    last_insn_signum = sig_num;

    if (sig_num == SIGSEGV) {
        consecutive_sigsegv++;
        
        if (consecutive_sigsegv >= SIGSEGV_THRESHOLD) {
            printf("consecutive SIGSEGV %d\n", SIGSEGV_THRESHOLD);
            
            if (result_bitmap) {
                save_bitmap_results();
                free(result_bitmap);
            }
            
            _exit(10);
        }
    } else {
        consecutive_sigsegv = 0; 
    }

    if (executing_insn == 0) {
        // Something other than a hidden insn execution raised the signal,
        // so quit
        fprintf(stderr, "%s\n", strsignal(sig_num));
        exit(1);
    }

    // Jump to the next instruction (i.e. skip the illegal insn)
    uintptr_t insn_skip = (uintptr_t)(insn_page) + (insn_offset+1)*4;

    //aarch32
    uc->uc_mcontext.arm_pc = insn_skip;

}

void init_signal_handler(void (*handler)(int, siginfo_t*, void*), int signum)
{
    sigaltstack(&sig_stack, NULL);

    struct sigaction s = {
        .sa_sigaction = handler,
        .sa_flags = SA_SIGINFO | SA_ONSTACK,
    };

    sigfillset(&s.sa_mask);

    sigaction(signum,  &s, NULL);
}


void execution_boilerplate(void)
{
        asm volatile(
            ".global boilerplate_start  \n"
            "boilerplate_start:         \n"

            // Store all gregs
            "push {r0-r12, lr}          \n"

            /*
             * It's better to use ptrace in cases where the sp might
             * be corrupted, but storing the sp in a vector reg
             * mitigates the issue somewhat.
             */
            "vmov s0, sp                \n"

            // Reset the regs to make insn execution deterministic
            // and avoid program corruption
            "mov r0, %[reg_init]        \n"
            "mov r1, %[reg_init]        \n"
            "mov r2, %[reg_init]        \n"
            "mov r3, %[reg_init]        \n"
            "mov r4, %[reg_init]        \n"
            "mov r5, %[reg_init]        \n"
            "mov r6, %[reg_init]        \n"
            "mov r7, %[reg_init]        \n"
            "mov r8, %[reg_init]        \n"
            "mov r9, %[reg_init]        \n"
            "mov r10, %[reg_init]       \n"
            "mov r11, %[reg_init]       \n"
            "mov r12, %[reg_init]       \n"
            "mov lr, %[reg_init]        \n"
            "mov sp, %[reg_init]        \n"

            // Note: this msr insn must be directly above the nop
            // because of the -c option (excluding the label ofc)
           "msr cpsr_f, #0             \n"

            ".global insn_location      \n"
            "insn_location:             \n"

            // This instruction will be replaced with the one to be tested
            "nop                        \n"

            "vmov sp, s0                \n"

            // Restore all gregs
            "pop {r0-r12, lr}           \n"

            "bx lr                      \n"
            ".global boilerplate_end    \n"
            "boilerplate_end:           \n"
            :
            : [reg_init] "n" (0)
            );

}

int init_insn_page(void)
{
    // Allocate an executable page / memory region
    insn_page = mmap(NULL,
                       PAGE_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);

    if (insn_page == MAP_FAILED)
        return 1;

    uint32_t boilerplate_length = (&boilerplate_end - &boilerplate_start) / 4;

    // Load the boilerplate assembly
    uint32_t i;
    for ( i = 0; i < boilerplate_length; ++i)
        ((uint32_t*)insn_page)[i] = ((uint32_t*)&boilerplate_start)[i];

    insn_offset = (&insn_location - &boilerplate_start) / 4;

    return 0;
}

void execute_insn_page(uint8_t *insn_bytes, size_t insn_length)
{
    // Jumps to the instruction buffer
    void (*exec_page)() = (void(*)()) insn_page;

    

    // Update the first instruction in the instruction buffer
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);

    last_insn_signum = 0;

    /*
     * Clear insn_page (at the insn to be tested + the msr insn before)
     * in the d- and icache
     * (some instructions might be skipped otherwise.)
     */
    __clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);

    executing_insn = 1;

    // Jump to the instruction to be tested (and execute it)
    exec_page();

    executing_insn = 0;

    
}


size_t fill_insn_buffer(uint8_t *buf, size_t buf_size, uint32_t insn)
{
    if (buf_size < 4)
        return 0;
 
    else {
        buf[0] = insn & 0xff;
        buf[1] = (insn >> 8) & 0xff;
        buf[2] = (insn >> 16) & 0xff;
        buf[3] = (insn >> 24) & 0xff;
    }
    return 4;
}

uint64_t get_nano_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000L + ts.tv_nsec;
}

int main(int argc, char* argv[]){

    if(argc < 3) {
        perror("need argc > 3");
        return 1;
    }

    uint32_t start, end;
    start = (uint32_t)strtoul(argv[1], NULL, 10);
    end = (uint32_t)strtoul(argv[2], NULL, 10);

    if(argc >= 4) {
        file_number = atoi(argv[3]);
        // setenv
        char file_num_env[32];
        snprintf(file_num_env, sizeof(file_num_env), "%d", file_number);
        setenv("RESULT_FILE_NUMBER", file_num_env, 1);
    }

    time_t start_time = time(NULL);
    init_signal_handler(signal_handler, SIGILL);
    init_signal_handler(signal_handler, SIGSEGV);
    init_signal_handler(signal_handler, SIGTRAP);
    init_signal_handler(signal_handler, SIGBUS);


    if (init_insn_page() != 0) {
        perror("insn_page mmap failed");
        return 1;
    }

    
    uint64_t last_timestamp = get_nano_timestamp();
    

    char line[100]; //用于存储每行数据

    if (init_bitmap(start, end) != 0) {
        fprintf(stderr, "init bitmap failed\n");
        munmap(insn_page, PAGE_SIZE);
        return 1;
    }

    for (uint32_t i = start; i < end; i++) {
        //printf("%d ", i);
        hidden_insn = i;

        cnt++;
        int flag=0;

        
        uint8_t insn_bytes[4];
        size_t buf_length = fill_insn_buffer(insn_bytes,
                                            sizeof(insn_bytes),
                                            hidden_insn);

        execute_insn_page(insn_bytes, buf_length);

        if (last_insn_signum == SIGILL) {
            sigill_cnt++;
            printf("0x%08x sigill : %d\n",hidden_insn,sigill_cnt);
        } else if (last_insn_signum == SIGSEGV) {
            sigsegv_cnt++;
            printf("0x%08x sigsegv: %d\n", hidden_insn, sigsegv_cnt);
        } else if (last_insn_signum == SIGBUS) {
            sigbus_cnt++;
            printf("0x%08x sigbus: %d\n", hidden_insn, sigbus_cnt);
        } else if (last_insn_signum == SIGTRAP) {
            printf("0x%08x sigtrap: %d\n", hidden_insn, sigtrap_cnt);
        } else{
            no_signal++;
            printf("0x%08x nosignal: %d\n", hidden_insn, no_signal);
            mark_executable(hidden_insn); 
        }
        instructions_checked++;
    } 
    munmap(insn_page, PAGE_SIZE);
    printf("Total insn numbers (checked):%d \n", instructions_checked);
    printf("SIGILL: %d\n", sigill_cnt);
    printf("SIGSEGV: %d\n", sigsegv_cnt);
    printf("SIGBUS: %d\n", sigbus_cnt);
    printf("SIGTRAP: %d\n", sigtrap_cnt);

    save_bitmap_results(); 
    
    if (result_bitmap) {
        free(result_bitmap);
        result_bitmap = NULL;
    }

    return 0;
        
}

