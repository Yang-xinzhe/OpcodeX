#define _GNU_SOURCE   
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pthread.h>   


#define EXIT_CONSECUTIVE_SIGSEGV 10 // Special exit code (corrupt stack)
#define MAX_RANGES 200000
#define NUM_CORES 4 

FILE *problem_ranges_file = NULL;

struct Range {
    uint32_t start;
    uint32_t end;
    int status; // 0: unprocessed 1:processing 2:processed
};

struct Worker {
    pid_t pid; // child pid
    int core_id;
    int busy; //flag
    int range_index; 
    time_t start_time; 
};

int set_cpu_affinity(pid_t pid, int core_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (sched_setaffinity(pid, sizeof(mask), &mask) < 0) {
        perror("Setting CPU affinity failed");
        return -1;
    }
    return 0;
}

int main() {

    if(access("./ins_check", X_OK) != 0) {
        fprintf(stderr, "cannnot execute instruction_tester\n");
        return 1;
    }

    problem_ranges_file = fopen("problem_ranges.txt", "a");
    if (!problem_ranges_file) {
        fprintf(stderr, "无法创建问题区间日志文件\n");
        return 1;
    }

    for(int file_num = 0 ; file_num < 256 ; ++file_num) {

        uint32_t cnt = 0;
        uint32_t sigsegv_cnt = 0;
        uint32_t sigill_cnt = 0;
        uint32_t sigtrap_cnt = 0;
        uint32_t sigbus_cnt = 0;
        uint32_t success_cnt = 0;
        uint32_t other_errors = 0;
        uint32_t instructions_checked = 0;

        char input_filename[100] = {0};
        snprintf(input_filename, sizeof(input_filename), "../armv8-a反汇编器/results_A32/res%d.txt", file_num);

        // Using bitmap to store instruction test result

        FILE *undefined_res = fopen(input_filename, "r");
        if(!undefined_res) {
            fprintf(stderr, "open %s failed: %s\n", input_filename, strerror(errno));
            continue;
        }

        struct Range range[MAX_RANGES]; // store each res file's interval
        int range_count = 0;

        // Using bitmap to store instruction test result
        // TODO: store result in bitmap

        char line[256];
        while(fgets(line, sizeof(line), undefined_res) != NULL&& range_count < MAX_RANGES) {
            uint32_t start, end;
            if(sscanf(line, "[%u, %u]", &start, &end) == 2) {
                range[range_count].start = start;
                range[range_count].end = end;
                range[range_count].status = 0; // unprocessed
                range_count++;
            }
        }
        fclose(undefined_res);
        printf("Read from undefined result %s %d intervals\n", input_filename, range_count);

        if(range_count == 0) {
            continue; // next res file
        }

        struct Worker workers[NUM_CORES];
        for(int i = 0 ; i < NUM_CORES ; ++i) {
            workers[i].pid = -1; // initial 
            workers[i].core_id = i;
            workers[i].busy = 0;
            workers[i].range_index = -1; 
        }

        int range_completed = 0;

        while(range_completed < range_count) {
            for(int w = 0; w < NUM_CORES ; ++w) {
                if(!workers[w].busy){
                    int next_range = -1;
                    for(int r = 0 ; r < range_count ; ++r) {
                        if(range[r].status == 0) { // unprocessed
                            next_range = r;
                            break;
                        }
                    }

                    if(next_range != -1) {
                        pid_t pid = fork();


                        if(pid < 0) {
                            // fork failed
                            perror("fork failed!");
                        } else if (pid == 0) {
                            // child process
                            if(set_cpu_affinity(getpid(), workers[w].core_id) < 0) {
                                fprintf(stderr, "Cannot set child process %d to core %d", getpid(), workers[w].core_id);
                            }

                            char start_str[20], end_str[20], file_num_str[20]; // child process need argv
                            snprintf(start_str, sizeof(start_str), "%u", range[next_range].start);
                            snprintf(end_str, sizeof(end_str), "%u", range[next_range].end);
                            snprintf(file_num_str, sizeof(file_num_str), "%d", file_num);
                            // TODO: OUTPUT FILE

                            execl("./ins_check", "ins_check", start_str, end_str, file_num_str, NULL);

                            perror("./ins_check failed!");
                            _exit(1);
                        } else {
                            // father process
                            workers[w].pid = pid;
                            workers[w].busy = 1; //flag
                            workers[w].range_index = next_range;
                            workers[w].start_time = time(NULL);
                            range[next_range].status = 1; // processing

                            printf("Core %d testing interval [%u, %u]\n", workers[w].core_id, range[next_range].start, range[next_range].end);
                        }
                    }
                }
            }


            // Checking Process
            for(int w = 0 ; w < NUM_CORES ; ++w){
                time_t current_time = time(NULL);
                if(workers[w].busy) {

                    if(current_time - workers[w].start_time > 1200) { // 20 min timecap
                        int range_idx = workers[w].range_index;

                        printf("Core: %d testing interval [%u, %u] TIMEOUT after 20 minutes, killing process\n", workers[w].core_id, range[range_idx].start, range[range_idx].end);

                        fprintf(problem_ranges_file, "file: %d [%u, %u] timeout\n", file_num, range[range_idx].start, range[range_idx].end);
                        fflush(problem_ranges_file);

                        kill(workers[w].pid, SIGKILL);

                        waitpid(workers[w].pid, NULL, 0);

                        range[range_idx].status = 2; // processed
                        range_completed++;

                        // reset process status
                        workers[w].pid = -1;
                        workers[w].busy = 0;
                        workers[w].range_index = -1;

                        continue; 
                    }    

                    int status;
                    pid_t result = waitpid(workers[w].pid, &status, WNOHANG);

                    if(result > 0) {
                        // child process completed
                        int range_idx = workers[w].range_index;

                        if(WIFEXITED(status)) {
                            int exit_code = WEXITSTATUS(status);

                            if(exit_code == 0) {
                                // complete normally
                                range[range_idx].status = 2; // processed
                                range_completed++;

                                printf("Core %d complete [%u, %u]\n", workers[w].core_id, range[range_idx].start, range[range_idx].end);
                            } else if (exit_code == EXIT_CONSECUTIVE_SIGSEGV) {
                                // consecutive SIGSEGV
                                printf("Core %d process [%u, %u] raise consecutive SIGSEGV\n", workers[w].core_id, range[range_idx].start, range[range_idx].end);
                                fprintf(problem_ranges_file, "file: %d [%u, %u]\n", file_num, range[range_idx].start, range[range_idx].end);
                                fflush(problem_ranges_file);

                                range[range_idx].start = 2; //processed
                                range_completed++;
                            } else {
                                // unexpectedly exit
                                printf("Core %d process [%u, %u] failed error=%d\n", workers[w].core_id, range[range_idx].start, range[range_idx].end, exit_code);
                                range[range_idx].status = 0;
                            }
                        } else {
                            // Terminate by signal
                            printf("Core %d process [%u, %u] get terminated by signal\n", workers[w].core_id, range[range_idx].start,range[range_idx].end);
                        }

                        // reset process status
                        workers[w].pid = -1;
                        workers[w].busy = 0;
                        workers[w].range_index = -1;
                    }
                }
            }

        }
        uint32_t total_instructions = 0;
        for(int r = 0 ; r < range_count ; ++r) {
            total_instructions += (range[r].end - range[r].start);
        }
        printf("Totally Processed %u instrustions in %d intervals\n", total_instructions, range_count);

    }
    if(problem_ranges_file) {
        fclose(problem_ranges_file);
    }
    return 0;
}