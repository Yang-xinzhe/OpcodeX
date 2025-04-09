#include <vector>
#include <map>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/shm.h>

extern "C" {
    void *insn_page;
    extern char insn_test_plate_begin, insn_test_plate_end, insn_location;
    uint32_t insn_offset;
    extern char insn_test_plate_begin, insn_test_plate_end, insn_location;
}

typedef __attribute__((aligned(4))) struct {
    uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12;
    uint32_t sp, lr, pc;
    uint32_t cpsr;
} RegisterStates;

using namespace std;

void test_instruction(void)
{

    asm volatile(
        ".global insn_test_plate_begin \n"
        "insn_test_plate_begin:\n"

        "push {r0-r10, r12, lr} \n"
        "movw r0, #:lower16:0x60000000 \n"
        "movt r0, #:upper16:0x60000000 \n"

        "ldr r1, [sp, #0]      \n"
        "str r1, [r0, #0]      \n"
        "ldr r1, [sp, #4]      \n"
        "str r1, [r0, #4]      \n"
        "ldr r1, [sp, #8]      \n"
        "str r1, [r0, #8]      \n"
        "ldr r1, [sp, #12]     \n"
        "str r1, [r0, #12]     \n"
        "ldr r1, [sp, #16]     \n"
        "str r1, [r0, #16]     \n"
        "ldr r1, [sp, #20]     \n"
        "str r1, [r0, #20]     \n"
        "ldr r1, [sp, #24]     \n"
        "str r1, [r0, #24]     \n"
        "ldr r1, [sp, #28]     \n"
        "str r1, [r0, #28]     \n"
        "ldr r1, [sp, #32]     \n"
        "str r1, [r0, #32]     \n"
        "ldr r1, [sp, #36]     \n"
        "str r1, [r0, #36]     \n"
        "ldr r1, [sp, #40]     \n"
        "str r1, [r0, #40]     \n"
        "ldr r1, [sp, #44]     \n"
        "str r1, [r0, #48]     \n"
        "ldr r1, [sp, #48]     \n"
        "str r1, [r0, #56]     \n"
        "ldr r1, [sp, #0]      \n"
        "str r1, [r0, #0]      \n"
        "mrs r1, cpsr          \n"
        "str r1, [r0, #64]     \n"
        "mov r1, sp            \n"
        "add r1, r1, #52       \n"
        "str r1, [r0, #52]     \n"
        "str pc, [r0, #60]     \n"
        "pop {r0-r10, r12, lr} \n"

        ".global insn_location \n"
        "insn_location: \n"
        "nop \n"

        "push {r0-r10, r12, lr} \n"
        "ldr r0, =0x60000000   \n"
        "add r0, r0, #68       \n"

        "str pc, [r0, #60]     \n"
        "ldr r1, [sp, #0]      \n" 
        "str r1, [r0, #0]      \n" 
        "ldr r1, [sp, #4]      \n"
        "str r1, [r0, #4]      \n"
        "ldr r1, [sp, #8]      \n"
        "str r1, [r0, #8]      \n"
        "ldr r1, [sp, #12]     \n"
        "str r1, [r0, #12]     \n"
        "ldr r1, [sp, #16]     \n"
        "str r1, [r0, #16]     \n"
        "ldr r1, [sp, #20]     \n"
        "str r1, [r0, #20]     \n"
        "ldr r1, [sp, #24]     \n"
        "str r1, [r0, #24]     \n"
        "ldr r1, [sp, #28]     \n"
        "str r1, [r0, #28]     \n"
        "ldr r1, [sp, #32]     \n"
        "str r1, [r0, #32]     \n"
        "ldr r1, [sp, #36]     \n"
        "str r1, [r0, #36]     \n"
        "ldr r1, [sp, #40]     \n"
        "str r1, [r0, #40]     \n"
        "ldr r1, [sp, #44]     \n"
        "str r1, [r0, #48]     \n"
        "ldr r1, [sp, #48]     \n"
        "str r1, [r0, #56]     \n"
        "ldr r1, [sp, #48]     \n"
        "str r1, [r0, #56]     \n"
        
        "mrs r1, cpsr          \n"
        "str r1, [r0, #64]     \n"
        "mov r1, sp            \n"
        "add r1, r1, #52       \n"
        "str r1, [r0, #52]     \n"
        "pop {r0-r10, r12, lr} \n"

        "bx lr \n"

        ".global insn_test_plate_end \n"
        "insn_test_plate_end: \n"
        :
        :
        : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r12", "lr", "memory", "cc");
}

int init_insn_page(void) {
    insn_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(insn_page == MAP_FAILED) {
        std::cerr << "insn_mmap failed" << std::endl;
        return 1;
    }

    uint32_t insn_test_plate_length = (&insn_test_plate_end - &insn_test_plate_begin);
    // printf("Debug: template length = %d bytes\n", insn_test_plate_length);
    memcpy(insn_page, &insn_test_plate_begin, insn_test_plate_length);

    // printf("\nCopied instructions in insn_page:\n");
    // uint32_t *dest = (uint32_t*)insn_page;
    // for(int i = 0; i < insn_test_plate_length/4; i++) {
    //     printf("%03d: 0x%08x\n", i, dest[i]);
    // }

    insn_offset = (&insn_location - &insn_test_plate_begin) / 4;
    // printf("insn_offset = %d\n", insn_offset);
    return 0;
}

void execute_insn_page(uint8_t *insn_bytes, size_t insn_length)
{
    // Jumps to the instruction buffer
    void (*exec_page)() = (void(*)()) insn_page;
    // Update the first instruction in the instruction buffer
    memcpy(insn_page + insn_offset * 4, insn_bytes, insn_length);
    __builtin___clear_cache(insn_page + (insn_offset-1) * 4,
                  insn_page + insn_offset * 4 + insn_length);
    exec_page();
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

// Helper function to print register states
void print_register_states(const char* title, const RegisterStates& regs) {
    std::cout << "========== " << title << " ==========" << std::endl;
    std::cout << "通用寄存器:" << std::endl;
    std::cout << "R0: 0x" << std::hex << std::setw(8) << std::setfill('0') << regs.r0 
              << "    R1: 0x" << std::setw(8) << regs.r1 
              << "    R2: 0x" << std::setw(8) << regs.r2 
              << "    R3: 0x" << std::setw(8) << regs.r3 << std::dec << std::endl;
    std::cout << "R4: 0x" << std::hex << std::setw(8) << regs.r4 
              << "    R5: 0x" << std::setw(8) << regs.r5 
              << "    R6: 0x" << std::setw(8) << regs.r6 
              << "    R7: 0x" << std::setw(8) << regs.r7 << std::dec << std::endl;
    std::cout << "R8: 0x" << std::hex << std::setw(8) << regs.r8 
              << "    R9: 0x" << std::setw(8) << regs.r9 
              << "    R10: 0x" << std::setw(8) << regs.r10 
              << "   R11: 0x" << std::setw(8) << regs.r11 << std::dec << std::endl; // Assuming R11 is saved/relevant
    std::cout << "R12: 0x" << std::hex << std::setw(8) << regs.r12 << std::dec << std::endl;

    std::cout << std::endl << "特殊寄存器:" << std::endl;
    std::cout << "SP: 0x" << std::hex << std::setw(8) << regs.sp 
              << "    LR: 0x" << std::setw(8) << regs.lr 
              << "    PC: 0x" << std::setw(8) << regs.pc << std::dec << std::endl;
    std::cout << "CPSR: 0x" << std::hex << std::setw(8) << regs.cpsr << std::dec << std::endl;

    // 分析CPSR
    uint32_t cpsr = regs.cpsr;
    std::cout << std::endl << "CPSR条件标志位:" << std::endl;
    std::cout << "N=" << ((cpsr >> 31) & 1) << " Z=" << ((cpsr >> 30) & 1) 
              << " C=" << ((cpsr >> 29) & 1) << " V=" << ((cpsr >> 28) & 1) 
              << " (0x" << std::hex << ((cpsr >> 28) & 0xF) << std::dec << ")" << std::endl;

    std::cout << "模式: ";
    uint32_t mode = cpsr & 0x1F;
    switch(mode) {
        case 0x10: std::cout << "用户模式 (USR)"; break;
        case 0x11: std::cout << "快速中断模式 (FIQ)"; break;
        case 0x12: std::cout << "中断模式 (IRQ)"; break;
        case 0x13: std::cout << "管理模式 (SVC)"; break;
        case 0x17: std::cout << "中止模式 (ABT)"; break;
        case 0x1B: std::cout << "未定义模式 (UND)"; break;
        case 0x1F: std::cout << "系统模式 (SYS)"; break;
        default: std::cout << "未知模式 (0x" << std::hex << mode << std::dec << ")";
    }
    std::cout << std::endl;

    std::cout << "中断状态: I=" << ((cpsr >> 7) & 1) << " F=" << ((cpsr >> 6) & 1)
              << " (IRQ " << (((cpsr >> 7) & 1) ? "禁用" : "启用") 
              << ", FIQ " << (((cpsr >> 6) & 1) ? "禁用" : "启用") << ")" << std::endl;
    std::cout << "===============================" << std::endl;
}

int main(int argc, char* argv[]) {

    uint32_t instruction_to_test = 0xe1500001; // CMP R0, R1
    std::cout << "Testing single instruction: " << std::hex << instruction_to_test << std::dec << std::endl;


    uint8_t insn_byte[4];
    const uint32_t MARKER_VALUE = 0xDEADBEEF;

    if(init_insn_page() != 0) {
        std::cerr << "init_insn_page failed" << std::endl;
        return 1;
    }

    int shmid = shmget(IPC_PRIVATE, sizeof(RegisterStates) * 2, IPC_CREAT | 0666);
    if(shmid == -1) {
        std::cerr << "shmget failed" << std::endl;
        return 1;
    }

    void *addr = (void *)0x60000000;
    void *res = shmat(shmid, addr, 0);
    if(res == (void *)-1 || res != addr) {
        std::cerr << "shmat failed or address mismatch" << std::endl;
        shmctl(shmid, IPC_RMID, NULL);
        return 1;
    }

    RegisterStates *regs_before_ptr = static_cast<RegisterStates*>(res);
    RegisterStates *regs_after_ptr = regs_before_ptr + 1;

    std::cout << "Setting marker value in regs_after region..." << std::endl;
    // Iterate through the RegisterStates struct as an array of uint32_t
    uint32_t* regs_after_words = reinterpret_cast<uint32_t*>(regs_after_ptr);
    size_t num_fields = sizeof(RegisterStates) / sizeof(uint32_t);
    for (size_t i = 0; i < num_fields; ++i) {
        regs_after_words[i] = MARKER_VALUE;
    }

    size_t buf_length = fill_insn_buffer(insn_byte, sizeof(insn_byte), instruction_to_test);
    if (buf_length == 0) {
         std::cerr << "Error filling buffer for instruction" << std::endl;
         shmdt(res);
         shmctl(shmid, IPC_RMID, NULL);
         return 1;
    }

    std::cout << "Executing instruction..." << std::endl;
    execute_insn_page(insn_byte, buf_length);
    std::cout << "Execution finished." << std::endl;

    bool abnormal_flow = (regs_after_ptr->pc == MARKER_VALUE && regs_after_ptr->cpsr == MARKER_VALUE);

    if(abnormal_flow) {
        std::cout << "**Abnormal flow detected! ***" << std::endl;
        print_register_states("(Abnormal Flow)", *regs_before_ptr);
    } else {
        std::cout << "Execution Flow normal" << std::endl;
        print_register_states("Register State Before" , *regs_before_ptr);
        std::cout << std::endl;
        print_register_states("Register State After", *regs_after_ptr);
    }

    shmdt(res);
    shmctl(shmid, IPC_RMID, NULL);

    std::cout << "Test Completed" << std::endl;
    return 0;
}

