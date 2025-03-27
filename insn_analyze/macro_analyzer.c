#include <stdio.h>
#include <stdint.h>

// 测试一组预定义的指令
// void test_predefined_instructions(uint32_t insn_value) {
//     uint32_t r0_before = 0xa5;
//     uint32_t r1_before = 0xa5;
//     uint32_t r0_after = 0, r1_after = 0;
    
//     printf("测试指令: 0x%08x\n", insn_value);
    
//     // 定义一个宏，为每个可能的指令生成测试代码
//     #define TEST_INSN(insn_hex) \
//     if (insn_value == insn_hex) { \
//         asm volatile( \
//             "mov r0, %[v0] \n" \
//             "mov r1, %[v1] \n" \
//             ".word " #insn_hex "\n" \
//             "mov %[r0], r0 \n" \
//             "mov %[r1], r1 \n" \
//             : [r0] "=r" (r0_after), [r1] "=r" (r1_after) \
//             : [v0] "r" (r0_before), [v1] "r" (r1_before) \
//             : "r0", "r1" \
//         ); \
//         printf("初始值: r0=0x%08x, r1=0x%08x\n", r0_before, r1_before); \
//         printf("执行后: r0=0x%08x, r1=0x%08x\n", r0_after, r1_after); \
//         printf("结果: %s\n", (r0_before != r0_after || r1_before != r1_after) ? \
//             "寄存器已改变" : "无变化"); \
//         return; \
//     }
    
//     // // 测试多组常见指令
//     // TEST_INSN(0xE1A00000)  // nop
//     // TEST_INSN(0xE1A00001)  // mov r0, r1
//     // TEST_INSN(0xE1A01000)  // mov r1, r0
//     // TEST_INSN(0xE1A00002)  // mov r0, r2
//     // // ...可以添加更多指令
//     TEST_INSN(0x00000008)
//     // 如果没有匹配的指令，报告错误
//     printf("未找到匹配的预定义指令测试\n");
// }

// void test_predefined_instructions(uint32_t insn_value) {
//     uint32_t r0_before = 0x11111111;
//     uint32_t r1_before = 0x22222222;
//     uint32_t r2_before = 0xa5;
//     uint32_t r3_before = 0xa5;
//     uint32_t r4_before = 0xa5;
//     uint32_t r5_before = 0xa5;
//     uint32_t r6_before = 0xa5;
//     uint32_t r7_before = 0xa5;
//     uint32_t r8_before = 0xa5;
//     uint32_t r0_after = 0, r1_after = 0, r2_after = 0, r3_after = 0, r4_after = 0, r5_after = 0, r6_after = 0, r7_after = 0, r8_after = 0;
//     uint32_t cpsr_before = 0, cpsr_after = 0;
//     uint32_t lr_before = 0, lr_after = 0;
//     uint32_t sp_before = 0, sp_after = 0;
//     uint32_t pc_before = 0, pc_after = 0;
//     printf("测试指令: 0x%08x\n", insn_value);
    
//     #define TEST_INSN(insn_hex) \
//     if (insn_value == insn_hex) { \
//         asm volatile( \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_b] \n" \
//             \
//             "mov r9, lr \n" \
//             "str r9, %[lr_b] \n" \
//             \
//             "mov r9, sp \n" \
//             "str r9, %[sp_b] \n" \
//             \
//             "ldr r0, %[v0] \n" \
//             "ldr r1, %[v1] \n" \
//             "ldr r2, %[v2] \n" \
//             "ldr r3, %[v3] \n" \
//             "ldr r4, %[v4] \n" \
//             "ldr r5, %[v5] \n" \
//             "ldr r6, %[v6] \n" \
//             "ldr r7, %[v7] \n" \
//             "ldr r8, %[v8] \n" \
//             \
//             "mov r9, pc \n" \
//             "str r9, %[pc_b] \n" \
//             \
//             ".word " #insn_hex "\n" \
//              "mov r9, pc \n" \
//             "str r9, %[pc_a] \n" \
//             \
//             "str r0, %[r0] \n" \
//             "str r1, %[r1] \n" \
//             "str r2, %[r2] \n" \
//             "str r3, %[r3] \n" \
//             "str r4, %[r4] \n" \
//             "str r5, %[r5] \n" \
//             "str r6, %[r6] \n" \
//             "str r7, %[r7] \n" \
//             "str r8, %[r8] \n" \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_a] \n" \
//             \
//             "mov r9, lr \n" \
//             "str r9, %[lr_a] \n" \
//             \
//              "mov r9, sp \n" \
//             "str r9, %[sp_a] \n" \
//             \
//             : [r0] "=m" (r0_after), [r1] "=m" (r1_after), \
//               [r2] "=m" (r2_after), [r3] "=m" (r3_after), \
//               [r4] "=m" (r4_after), [r5] "=m" (r5_after), \
//               [r6] "=m" (r6_after), [r7] "=m" (r7_after), \
//               [r8] "=m" (r8_after), \
//               [cpsr_b] "=m" (cpsr_before), [cpsr_a] "=m" (cpsr_after), \
//               [lr_b] "=m" (lr_before), [lr_a] "=m" (lr_after), \
//               [sp_b] "=m" (sp_before), [sp_a] "=m" (sp_after), \
//               [pc_b] "=m" (pc_before), [pc_a] "=m" (pc_after) \
//             : [v0] "m" (r0_before), [v1] "m" (r1_before), \
//               [v2] "m" (r2_before), [v3] "m" (r3_before), \
//               [v4] "m" (r4_before), [v5] "m" (r5_before), \
//               [v6] "m" (r6_before), [v7] "m" (r7_before), \
//               [v8] "m" (r8_before) \
//             : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9" \
//         ); \
//         printf("初始值: r0=0x%08x, r1=0x%08x\n", r0_before, r1_before); \
//         printf("执行后: r0=0x%08x, r1=0x%08x\n", r0_after, r1_after); \
//         printf("执行后: r2=0x%08x, r3=0x%08x\n", r2_after, r3_after); \
//         printf("执行后: r4=0x%08x, r5=0x%08x\n", r4_after, r5_after); \
//         printf("执行后: r6=0x%08x, r7=0x%08x\n", r6_after, r7_after); \
//         printf("执行后: r8=0x%08x\n", r8_after); \
//         printf("结果: %s\n", (r0_before != r0_after || r1_before != r1_after) ? \
//             "寄存器已改变" : "无变化"); \
//         printf("\n=== 特殊寄存器 ===\n"); \
//         printf("CPSR: 0x%08x -> 0x%08x %s\n", cpsr_before, cpsr_after, \
//                (cpsr_before != cpsr_after) ? "已改变" : ""); \
//         \
//         /* 分析CPSR变化 */ \
//         if(cpsr_before != cpsr_after) { \
//             printf("CPSR标志位: "); \
//             if((cpsr_before & 0x80000000) != (cpsr_after & 0x80000000)) \
//                 printf("N "); /* 负数标志 */ \
//             if((cpsr_before & 0x40000000) != (cpsr_after & 0x40000000)) \
//                 printf("Z "); /* 零标志 */ \
//             if((cpsr_before & 0x20000000) != (cpsr_after & 0x20000000)) \
//                 printf("C "); /* 进位标志 */ \
//             if((cpsr_before & 0x10000000) != (cpsr_after & 0x10000000)) \
//                 printf("V "); /* 溢出标志 */ \
//             printf("\n"); \
//         } \
//         \
//         printf("LR: 0x%08x -> 0x%08x %s\n", lr_before, lr_after, \
//                (lr_before != lr_after) ? "已改变" : ""); \
//         \
//         printf("SP: 0x%08x -> 0x%08x %s\n", sp_before, sp_after, \
//                (sp_before != sp_after) ? "已改变" : ""); \
//         printf("PC: 0x%08x -> 0x%08x %s\n", pc_before, pc_after, \
//                (pc_after != pc_before + 12) ? "非顺序执行" : "顺序执行"); \
//         \
//         return; \
// }\
    
//     TEST_INSN(0x00000008)
//     TEST_INSN(0xe1a00001)
//     TEST_INSN(0xe1a00002)
    
//     printf("未找到匹配的预定义指令测试\n");
// }

// void test_predefined_instructions(uint32_t insn_value) {
//     uint32_t r0_before = 0, r1_before = 0, r2_before = 0, r3_before = 0;
//     uint32_t r4_before = 0, r5_before = 0, r6_before = 0, r7_before = 0, r8_before = 0, r9_before = 0;
//     uint32_t r0_after = 0, r1_after = 0, r2_after = 0, r3_after = 0;
//     uint32_t r4_after = 0, r5_after = 0, r6_after = 0, r7_after = 0, r8_after = 0, r9_after = 0;
//     uint32_t cpsr_before = 0, cpsr_after = 0;
//     uint32_t lr_before = 0, lr_after = 0;
//     uint32_t sp_before = 0, sp_after = 0;
//     uint32_t pc_before = 0, pc_after = 0;
    
//     printf("测试指令: 0x%08x\n", insn_value);
    
//     #define TEST_INSN(insn_hex) \
//     if (insn_value == insn_hex) { \
//         asm volatile( \
//             /* 保存执行前的CPSR和特殊寄存器 */ \
//             "str r9, %[r9_b] \n" \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_b] \n" \
//             "mov r9, lr \n" \
//             "str r9, %[lr_b] \n" \
//             "mov r9, sp \n" \
//             "str r9, %[sp_b] \n" \
//             \
//             /* 保存执行前的普通寄存器 */ \
//             "str r0, %[r0_b] \n" \
//             "str r1, %[r1_b] \n" \
//             "str r2, %[r2_b] \n" \
//             "str r3, %[r3_b] \n" \
//             "str r4, %[r4_b] \n" \
//             "str r5, %[r5_b] \n" \
//             "str r6, %[r6_b] \n" \
//             "str r7, %[r7_b] \n" \
//             "str r8, %[r8_b] \n" \
//             \
//             /* 获取PC值 */ \
//             "mov r9, pc \n" \
//             "str r9, %[pc_b] \n" \
//             \
//             /* 执行测试指令 */ \
//             ".word " #insn_hex "\n" \
//             \
//             /* 立即记录PC值 */ \
//             "mov r9, pc \n" \
//             "str r9, %[pc_a] \n" \
//             \
//             /* 保存执行后的普通寄存器 */ \
//             "str r0, %[r0_a] \n" \
//             "str r1, %[r1_a] \n" \
//             "str r2, %[r2_a] \n" \
//             "str r3, %[r3_a] \n" \
//             "str r4, %[r4_a] \n" \
//             "str r5, %[r5_a] \n" \
//             "str r6, %[r6_a] \n" \
//             "str r7, %[r7_a] \n" \
//             "str r8, %[r8_a] \n" \
//             \
//             /* 保存执行后的CPSR和特殊寄存器 */ \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_a] \n" \
//             "mov r9, lr \n" \
//             "str r9, %[lr_a] \n" \
//             "mov r9, sp \n" \
//             "str r9, %[sp_a] \n" \
//             \
//             : [r0_b] "=m" (r0_before), [r1_b] "=m" (r1_before), \
//               [r2_b] "=m" (r2_before), [r3_b] "=m" (r3_before), \
//               [r4_b] "=m" (r4_before), [r5_b] "=m" (r5_before), \
//               [r6_b] "=m" (r6_before), [r7_b] "=m" (r7_before), \
//               [r8_b] "=m" (r8_before), [r9_b] "=m" (r9_before),\
//               [r0_a] "=m" (r0_after), [r1_a] "=m" (r1_after), \
//               [r2_a] "=m" (r2_after), [r3_a] "=m" (r3_after), \
//               [r4_a] "=m" (r4_after), [r5_a] "=m" (r5_after), \
//               [r6_a] "=m" (r6_after), [r7_a] "=m" (r7_after), \
//               [r8_a] "=m" (r8_after), \
//               [cpsr_b] "=m" (cpsr_before), [cpsr_a] "=m" (cpsr_after), \
//               [lr_b] "=m" (lr_before), [lr_a] "=m" (lr_after), \
//               [sp_b] "=m" (sp_before), [sp_a] "=m" (sp_after), \
//               [pc_b] "=m" (pc_before), [pc_a] "=m" (pc_after) \
//             :: "r9", "memory" \
//         ); \
//         \
//         /* 打印寄存器状态 */ \
//         printf("初始寄存器状态:\n"); \
//         printf("  r0=0x%08x, r1=0x%08x, r2=0x%08x, r3=0x%08x\n", r0_before, r1_before, r2_before, r3_before); \
//         printf("  r4=0x%08x, r5=0x%08x, r6=0x%08x, r7=0x%08x\n", r4_before, r5_before, r6_before, r7_before); \
//         printf("  r8=0x%08x, r9=0x%08x\n", r8_before, r9_before); \
//         \
//         printf("\n执行后寄存器状态:\n"); \
//         printf("  r0=0x%08x %s\n", r0_after, (r0_before != r0_after) ? "[已改变]" : ""); \
//         printf("  r1=0x%08x %s\n", r1_after, (r1_before != r1_after) ? "[已改变]" : ""); \
//         printf("  r2=0x%08x %s\n", r2_after, (r2_before != r2_after) ? "[已改变]" : ""); \
//         printf("  r3=0x%08x %s\n", r3_after, (r3_before != r3_after) ? "[已改变]" : ""); \
//         printf("  r4=0x%08x %s\n", r4_after, (r4_before != r4_after) ? "[已改变]" : ""); \
//         printf("  r5=0x%08x %s\n", r5_after, (r5_before != r5_after) ? "[已改变]" : ""); \
//         printf("  r6=0x%08x %s\n", r6_after, (r6_before != r6_after) ? "[已改变]" : ""); \
//         printf("  r7=0x%08x %s\n", r7_after, (r7_before != r7_after) ? "[已改变]" : ""); \
//         printf("  r8=0x%08x %s\n", r8_after, (r8_before != r8_after) ? "[已改变]" : ""); \
//         \
//         printf("\n=== 特殊寄存器 ===\n"); \
//         printf("CPSR: 0x%08x -> 0x%08x %s\n", cpsr_before, cpsr_after, \
//                (cpsr_before != cpsr_after) ? "已改变" : ""); \
//         \
//         /* 分析CPSR变化 */ \
//         if(cpsr_before != cpsr_after) { \
//             printf("CPSR标志位: "); \
//             if((cpsr_before & 0x80000000) != (cpsr_after & 0x80000000)) \
//                 printf("N "); /* 负数标志 */ \
//             if((cpsr_before & 0x40000000) != (cpsr_after & 0x40000000)) \
//                 printf("Z "); /* 零标志 */ \
//             if((cpsr_before & 0x20000000) != (cpsr_after & 0x20000000)) \
//                 printf("C "); /* 进位标志 */ \
//             if((cpsr_before & 0x10000000) != (cpsr_after & 0x10000000)) \
//                 printf("V "); /* 溢出标志 */ \
//             printf("\n"); \
//         } \
//         \
//         printf("LR: 0x%08x -> 0x%08x %s\n", lr_before, lr_after, \
//                (lr_before != lr_after) ? "已改变" : ""); \
//         printf("SP: 0x%08x -> 0x%08x %s\n", sp_before, sp_after, \
//                (sp_before != sp_after) ? "已改变" : ""); \
//         printf("PC: 0x%08x -> 0x%08x %s\n", pc_before, pc_after, \
//                (pc_after != pc_before + 12) ? "非顺序执行" : "顺序执行"); \
//         \
//         return; \
//     } \
    
//     TEST_INSN(0x00000008)
//     TEST_INSN(0xe1a00001)
//     TEST_INSN(0xe1a00002)
    
//     printf("未找到匹配的预定义指令测试\n");
// }

/*=====================================================================*/
// void test_predefined_instructions(uint32_t insn_value) {
//     uint32_t r0_before = 0, r1_before = 0, r2_before = 0, r3_before = 0;
//     uint32_t r4_before = 0, r5_before = 0, r6_before = 0, r7_before = 0, r8_before = 0, r9_before = 0;
//     uint32_t r0_after = 0, r1_after = 0, r2_after = 0, r3_after = 0;
//     uint32_t r4_after = 0, r5_after = 0, r6_after = 0, r7_after = 0, r8_after = 0, r9_after = 0;
//     uint32_t cpsr_before = 0, cpsr_after = 0;
//     uint32_t lr_before = 0, lr_after = 0;
//     uint32_t sp_before = 0, sp_after = 0;
//     uint32_t pc_before = 0, pc_after = 0;
    
//     printf("测试指令: 0x%08x\n", insn_value);
    
//     #define TEST_INSN(insn_hex) \
//     if (insn_value == insn_hex) { \
//         asm volatile( \
//             /* 保存执行前的CPSR和特殊寄存器 */ \
//             "str r9, %[r9_b] \n" \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_b] \n" \
//             "str lr, %[lr_b] \n" \
//             "str sp, %[sp_b] \n" \
//             "ldr r9, %[r9_b] \n" \
//             \
//             /* 保存执行前的普通寄存器 */ \
//             "str r0, %[r0_b] \n" \
//             "str r1, %[r1_b] \n" \
//             "str r2, %[r2_b] \n" \
//             "str r3, %[r3_b] \n" \
//             "str r4, %[r4_b] \n" \
//             "str r5, %[r5_b] \n" \
//             "str r6, %[r6_b] \n" \
//             "str r7, %[r7_b] \n" \
//             "str r8, %[r8_b] \n" \
//             \
//             "str pc, %[pc_b] \n" \
//             /* 执行测试指令 */ \
//             ".word " #insn_hex "\n" \
//             \
//             "str pc, %[pc_a] \n" \
//             \
//             /* 保存执行后的普通寄存器 */ \
//             "str r0, %[r0_a] \n" \
//             "str r1, %[r1_a] \n" \
//             "str r2, %[r2_a] \n" \
//             "str r3, %[r3_a] \n" \
//             "str r4, %[r4_a] \n" \
//             "str r5, %[r5_a] \n" \
//             "str r6, %[r6_a] \n" \
//             "str r7, %[r7_a] \n" \
//             "str r8, %[r8_a] \n" \
//             "str r9, %[r9_a] \n" \
//             \
//             /* 保存执行后的CPSR和特殊寄存器 */ \
//             "mrs r9, cpsr \n" \
//             "str r9, %[cpsr_a] \n" \
//             "str lr, %[lr_a] \n" \
//             "str sp, %[sp_a] \n" \
//             \
//             : [r0_b] "=m" (r0_before), [r1_b] "=m" (r1_before), \
//               [r2_b] "=m" (r2_before), [r3_b] "=m" (r3_before), \
//               [r4_b] "=m" (r4_before), [r5_b] "=m" (r5_before), \
//               [r6_b] "=m" (r6_before), [r7_b] "=m" (r7_before), \
//               [r8_b] "=m" (r8_before), [r9_b] "=m" (r9_before),\
//               [r0_a] "=m" (r0_after), [r1_a] "=m" (r1_after), \
//               [r2_a] "=m" (r2_after), [r3_a] "=m" (r3_after), \
//               [r4_a] "=m" (r4_after), [r5_a] "=m" (r5_after), \
//               [r6_a] "=m" (r6_after), [r7_a] "=m" (r7_after), \
//               [r8_a] "=m" (r8_after), [r9_a] "=m" (r9_after), \
//               [cpsr_b] "=m" (cpsr_before), [cpsr_a] "=m" (cpsr_after), \
//               [lr_b] "=m" (lr_before), [lr_a] "=m" (lr_after), \
//               [sp_b] "=m" (sp_before), [sp_a] "=m" (sp_after), \
//               [pc_b] "=m" (pc_before), [pc_a] "=m" (pc_after) \
//             :: "r9", "memory" \
//         ); \
//         \
//         /* 打印寄存器状态 */ \
//         printf("初始寄存器状态:\n"); \
//         printf("  r0=0x%08x, r1=0x%08x, r2=0x%08x, r3=0x%08x\n", r0_before, r1_before, r2_before, r3_before); \
//         printf("  r4=0x%08x, r5=0x%08x, r6=0x%08x, r7=0x%08x\n", r4_before, r5_before, r6_before, r7_before); \
//         printf("  r8=0x%08x, r9=0x%08x\n", r8_before, r9_before); \
//         \
//         printf("\n执行后寄存器状态:\n"); \
//         printf("  r0=0x%08x %s\n", r0_after, (r0_before != r0_after) ? "[已改变]" : ""); \
//         printf("  r1=0x%08x %s\n", r1_after, (r1_before != r1_after) ? "[已改变]" : ""); \
//         printf("  r2=0x%08x %s\n", r2_after, (r2_before != r2_after) ? "[已改变]" : ""); \
//         printf("  r3=0x%08x %s\n", r3_after, (r3_before != r3_after) ? "[已改变]" : ""); \
//         printf("  r4=0x%08x %s\n", r4_after, (r4_before != r4_after) ? "[已改变]" : ""); \
//         printf("  r5=0x%08x %s\n", r5_after, (r5_before != r5_after) ? "[已改变]" : ""); \
//         printf("  r6=0x%08x %s\n", r6_after, (r6_before != r6_after) ? "[已改变]" : ""); \
//         printf("  r7=0x%08x %s\n", r7_after, (r7_before != r7_after) ? "[已改变]" : ""); \
//         printf("  r8=0x%08x %s\n", r8_after, (r8_before != r8_after) ? "[已改变]" : ""); \
//         printf("  r9=0x%08x %s\n", r9_after, (r9_before != r9_after) ? "[已改变]" : ""); \
//         \
//         printf("\n=== 特殊寄存器 ===\n"); \
//         printf("CPSR: 0x%08x -> 0x%08x %s\n", cpsr_before, cpsr_after, \
//                (cpsr_before != cpsr_after) ? "已改变" : ""); \
//         \
//         /* 分析CPSR变化 */ \
//         if(cpsr_before != cpsr_after) { \
//             printf("CPSR标志位: "); \
//             if((cpsr_before & 0x80000000) != (cpsr_after & 0x80000000)) \
//                 printf("N "); /* 负数标志 */ \
//             if((cpsr_before & 0x40000000) != (cpsr_after & 0x40000000)) \
//                 printf("Z "); /* 零标志 */ \
//             if((cpsr_before & 0x20000000) != (cpsr_after & 0x20000000)) \
//                 printf("C "); /* 进位标志 */ \
//             if((cpsr_before & 0x10000000) != (cpsr_after & 0x10000000)) \
//                 printf("V "); /* 溢出标志 */ \
//             printf("\n"); \
//         } \
//         \
//         printf("LR: 0x%08x -> 0x%08x %s\n", lr_before, lr_after, \
//                (lr_before != lr_after) ? "已改变" : ""); \
//         printf("SP: 0x%08x -> 0x%08x %s\n", sp_before, sp_after, \
//                (sp_before != sp_after) ? "已改变" : ""); \
//         printf("PC: 0x%08x -> 0x%08x %s\n", pc_before, pc_after, \
//                (pc_after != pc_before + 8) ? "非顺序执行" : "顺序执行"); \
//         \
//         return; \
//     } \
    
//     TEST_INSN(0x00000008)
//     TEST_INSN(0xe1a00001)
//     TEST_INSN(0xe1a00002)
//     TEST_INSN(0xE28DD010)
//     TEST_INSN(0xE12FFF1E)
//     TEST_INSN(0xE3500000)
//     TEST_INSN(0xE0900001)
    
//     printf("未找到匹配的预定义指令测试\n");
// }

// int main(int argc, char *argv[]) {
//     if (argc < 2) {
//         printf("用法: %s <指令值>\n", argv[0]);
//         return 1;
//     }
    
//     uint32_t insn_value;
//     sscanf(argv[1], "0x%x", &insn_value);
    
//     test_predefined_instructions(insn_value);
//     return 0;
// } 
/*=========================================================*/

#ifndef TEST_INSTRUCTION
#define TEST_INSTRUCTION 0xe1a00001 
#endif

#define STR(x) #x
#define XSTR(x) STR(x)

void test_predefined_instructions(void) {
    uint32_t r0_before = 0, r1_before = 0, r2_before = 0, r3_before = 0;
    uint32_t r4_before = 0, r5_before = 0, r6_before = 0, r7_before = 0, r8_before = 0, r9_before = 0;
    uint32_t r0_after = 0, r1_after = 0, r2_after = 0, r3_after = 0;
    uint32_t r4_after = 0, r5_after = 0, r6_after = 0, r7_after = 0, r8_after = 0, r9_after = 0;
    uint32_t cpsr_before = 0, cpsr_after = 0;
    uint32_t lr_before = 0, lr_after = 0;
    uint32_t sp_before = 0, sp_after = 0;
    uint32_t pc_before = 0, pc_after = 0;
    
    printf("测试指令: 0x%08x\n", TEST_INSTRUCTION);

    asm volatile(/* 保存执行前的CPSR和特殊寄存器 */
                 "str r9, %[r9_b] \n"
                 "mrs r9, cpsr \n"
                 "str r9, %[cpsr_b] \n"
                 "str lr, %[lr_b] \n"
                 "str sp, %[sp_b] \n"
                 "ldr r9, %[r9_b] \n"

                 /* 保存执行前的普通寄存器 */
                 "str r0, %[r0_b] \n"
                 "str r1, %[r1_b] \n"
                 "str r2, %[r2_b] \n"
                 "str r3, %[r3_b] \n"
                 "str r4, %[r4_b] \n"
                 "str r5, %[r5_b] \n"
                 "str r6, %[r6_b] \n"
                 "str r7, %[r7_b] \n"
                 "str r8, %[r8_b] \n"

                 "str pc, %[pc_b] \n"
                 ".word " XSTR(TEST_INSTRUCTION) "\n"

                 "str pc, %[pc_a] \n"

                 "str r0, %[r0_a] \n"
                 "str r1, %[r1_a] \n"
                 "str r2, %[r2_a] \n"
                 "str r3, %[r3_a] \n"
                 "str r4, %[r4_a] \n"
                 "str r5, %[r5_a] \n"
                 "str r6, %[r6_a] \n"
                 "str r7, %[r7_a] \n"
                 "str r8, %[r8_a] \n"
                 "str r9, %[r9_a] \n"

                 "mrs r9, cpsr \n"
                 "str r9, %[cpsr_a] \n"
                 "str lr, %[lr_a] \n"
                 "str sp, %[sp_a] \n"

                 : [r0_b] "=m"(r0_before), [r1_b] "=m"(r1_before),
                   [r2_b] "=m"(r2_before), [r3_b] "=m"(r3_before),
                   [r4_b] "=m"(r4_before), [r5_b] "=m"(r5_before),
                   [r6_b] "=m"(r6_before), [r7_b] "=m"(r7_before),
                   [r8_b] "=m"(r8_before), [r9_b] "=m"(r9_before),
                   [r0_a] "=m"(r0_after), [r1_a] "=m"(r1_after),
                   [r2_a] "=m"(r2_after), [r3_a] "=m"(r3_after),
                   [r4_a] "=m"(r4_after), [r5_a] "=m"(r5_after),
                   [r6_a] "=m"(r6_after), [r7_a] "=m"(r7_after),
                   [r8_a] "=m"(r8_after), [r9_a] "=m"(r9_after),
                   [cpsr_b] "=m"(cpsr_before), [cpsr_a] "=m"(cpsr_after),
                   [lr_b] "=m"(lr_before), [lr_a] "=m"(lr_after),
                   [sp_b] "=m"(sp_before), [sp_a] "=m"(sp_after),
                   [pc_b] "=m"(pc_before), [pc_a] "=m"(pc_after)::"r9", "memory");

    /* 打印寄存器状态 */
    printf("初始寄存器状态:\n");
    printf("  r0=0x%08x, r1=0x%08x, r2=0x%08x, r3=0x%08x\n", r0_before, r1_before, r2_before, r3_before);
    printf("  r4=0x%08x, r5=0x%08x, r6=0x%08x, r7=0x%08x\n", r4_before, r5_before, r6_before, r7_before);
    printf("  r8=0x%08x, r9=0x%08x\n", r8_before, r9_before);

    printf("\n执行后寄存器状态:\n");
    printf("  r0=0x%08x %s\n", r0_after, (r0_before != r0_after) ? "[已改变]" : "");
    printf("  r1=0x%08x %s\n", r1_after, (r1_before != r1_after) ? "[已改变]" : "");
    printf("  r2=0x%08x %s\n", r2_after, (r2_before != r2_after) ? "[已改变]" : "");
    printf("  r3=0x%08x %s\n", r3_after, (r3_before != r3_after) ? "[已改变]" : "");
    printf("  r4=0x%08x %s\n", r4_after, (r4_before != r4_after) ? "[已改变]" : "");
    printf("  r5=0x%08x %s\n", r5_after, (r5_before != r5_after) ? "[已改变]" : "");
    printf("  r6=0x%08x %s\n", r6_after, (r6_before != r6_after) ? "[已改变]" : "");
    printf("  r7=0x%08x %s\n", r7_after, (r7_before != r7_after) ? "[已改变]" : "");
    printf("  r8=0x%08x %s\n", r8_after, (r8_before != r8_after) ? "[已改变]" : "");
    printf("  r9=0x%08x %s\n", r9_after, (r9_before != r9_after) ? "[已改变]" : "");

    printf("\n=== 特殊寄存器 ===\n");
    printf("CPSR: 0x%08x -> 0x%08x %s\n", cpsr_before, cpsr_after,
           (cpsr_before != cpsr_after) ? "已改变" : "");

    /* 分析CPSR变化 */
    if (cpsr_before != cpsr_after)
    {
        printf("CPSR标志位: ");
        if ((cpsr_before & 0x80000000) != (cpsr_after & 0x80000000))
            printf("N "); /* 负数标志 */
        if ((cpsr_before & 0x40000000) != (cpsr_after & 0x40000000))
            printf("Z "); /* 零标志 */
        if ((cpsr_before & 0x20000000) != (cpsr_after & 0x20000000))
            printf("C "); /* 进位标志 */
        if ((cpsr_before & 0x10000000) != (cpsr_after & 0x10000000))
            printf("V "); /* 溢出标志 */
        printf("\n");
    }

    printf("LR: 0x%08x -> 0x%08x %s\n", lr_before, lr_after,
           (lr_before != lr_after) ? "已改变" : "");
    printf("SP: 0x%08x -> 0x%08x %s\n", sp_before, sp_after,
           (sp_before != sp_after) ? "已改变" : "");
    printf("PC: 0x%08x -> 0x%08x %s\n", pc_before, pc_after,
           (pc_after != pc_before + 8) ? "非顺序执行" : "顺序执行");

    return;
}

int main(int argc, char *argv[]) {
    test_predefined_instructions();
    return 0;
} 