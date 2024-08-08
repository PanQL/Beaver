#include <linux/types.h>

#define REGISTERS_1024 "%zmm0", "%zmm1", "%zmm2", "%zmm3", "%zmm4", "%zmm5", "%zmm6", "%zmm7", "%zmm8", "%zmm9", "%zmm10", "%zmm11", "%zmm12", "%zmm13", "%zmm14", "%zmm15"

#define REGISTERS_2048 "%zmm0", "%zmm1", "%zmm2", "%zmm3", "%zmm4", "%zmm5", "%zmm6", "%zmm7", "%zmm8", "%zmm9", "%zmm10", "%zmm11", "%zmm12", "%zmm13", "%zmm14", "%zmm15", "%zmm16", "%zmm17", "%zmm18", "%zmm19", "%zmm20", "%zmm21", "%zmm22", "%zmm23", "%zmm24", "%zmm25", "%zmm26", "%zmm27", "%zmm28", "%zmm29", "%zmm30", "%zmm31"

#define READ_NT_1024_ASM \
    "vmovntdqa 0*64(%[addr]),   %%zmm0 \n" \
    "vmovntdqa 1*64(%[addr]),   %%zmm1 \n" \
    "vmovntdqa 2*64(%[addr]),   %%zmm2 \n" \
    "vmovntdqa 3*64(%[addr]),   %%zmm3 \n" \
    "vmovntdqa 4*64(%[addr]),   %%zmm4 \n" \
    "vmovntdqa 5*64(%[addr]),   %%zmm5 \n" \
    "vmovntdqa 6*64(%[addr]),   %%zmm6 \n" \
    "vmovntdqa 7*64(%[addr]),   %%zmm7 \n" \
    "vmovntdqa 8*64(%[addr]),   %%zmm8 \n" \
    "vmovntdqa 9*64(%[addr]),   %%zmm9 \n" \
    "vmovntdqa 10*64(%[addr]),   %%zmm10 \n" \
    "vmovntdqa 11*64(%[addr]),   %%zmm11 \n" \
    "vmovntdqa 12*64(%[addr]),   %%zmm12 \n" \
    "vmovntdqa 13*64(%[addr]),   %%zmm13 \n" \
    "vmovntdqa 14*64(%[addr]),   %%zmm14 \n" \
    "vmovntdqa 15*64(%[addr]),   %%zmm15 \n"

#define WRITE_NT_1024_ASM \
    "vmovntdq   %%zmm0, 0*64(%[waddr]) \n" \
    "vmovntdq   %%zmm1, 1*64(%[waddr]) \n" \
    "vmovntdq   %%zmm2, 2*64(%[waddr]) \n" \
    "vmovntdq   %%zmm3, 3*64(%[waddr]) \n" \
    "vmovntdq   %%zmm4, 4*64(%[waddr]) \n" \
    "vmovntdq   %%zmm5, 5*64(%[waddr]) \n" \
    "vmovntdq   %%zmm6, 6*64(%[waddr]) \n" \
    "vmovntdq   %%zmm7, 7*64(%[waddr]) \n" \
    "vmovntdq   %%zmm8, 8*64(%[waddr]) \n" \
    "vmovntdq   %%zmm9, 9*64(%[waddr]) \n" \
    "vmovntdq  %%zmm10, 10*64(%[waddr]) \n" \
    "vmovntdq  %%zmm11, 11*64(%[waddr]) \n" \
    "vmovntdq  %%zmm12, 12*64(%[waddr]) \n" \
    "vmovntdq  %%zmm13, 13*64(%[waddr]) \n" \
    "vmovntdq  %%zmm14, 14*64(%[waddr]) \n" \
    "vmovntdq  %%zmm15, 15*64(%[waddr]) \n"

#define WRITE_NT_1024_ASM1 \
    "vmovntdq   %%zmm0, 0*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm1, 1*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm2, 2*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm3, 3*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm4, 4*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm5, 5*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm6, 6*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm7, 7*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm8, 8*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm9, 9*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm10, 10*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm11, 11*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm12, 12*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm13, 13*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm14, 14*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm15, 15*64(%[waddr1]) \n"

#define READ_NT_2048_ASM \
    "vmovntdqa 0*64(%[addr]),   %%zmm0 \n" \
    "vmovntdqa 1*64(%[addr]),   %%zmm1 \n" \
    "vmovntdqa 2*64(%[addr]),   %%zmm2 \n" \
    "vmovntdqa 3*64(%[addr]),   %%zmm3 \n" \
    "vmovntdqa 4*64(%[addr]),   %%zmm4 \n" \
    "vmovntdqa 5*64(%[addr]),   %%zmm5 \n" \
    "vmovntdqa 6*64(%[addr]),   %%zmm6 \n" \
    "vmovntdqa 7*64(%[addr]),   %%zmm7 \n" \
    "vmovntdqa 8*64(%[addr]),   %%zmm8 \n" \
    "vmovntdqa 9*64(%[addr]),   %%zmm9 \n" \
    "vmovntdqa 10*64(%[addr]),   %%zmm10 \n" \
    "vmovntdqa 11*64(%[addr]),   %%zmm11 \n" \
    "vmovntdqa 12*64(%[addr]),   %%zmm12 \n" \
    "vmovntdqa 13*64(%[addr]),   %%zmm13 \n" \
    "vmovntdqa 14*64(%[addr]),   %%zmm14 \n" \
    "vmovntdqa 15*64(%[addr]),   %%zmm15 \n" \
    "vmovntdqa 16*64(%[addr]),   %%zmm16 \n" \
    "vmovntdqa 17*64(%[addr]),   %%zmm17 \n" \
    "vmovntdqa 18*64(%[addr]),   %%zmm18 \n" \
    "vmovntdqa 19*64(%[addr]),   %%zmm19 \n" \
    "vmovntdqa 20*64(%[addr]),   %%zmm20 \n" \
    "vmovntdqa 21*64(%[addr]),   %%zmm21 \n" \
    "vmovntdqa 22*64(%[addr]),   %%zmm22 \n" \
    "vmovntdqa 23*64(%[addr]),   %%zmm23 \n" \
    "vmovntdqa 24*64(%[addr]),   %%zmm24 \n" \
    "vmovntdqa 25*64(%[addr]),   %%zmm25 \n" \
    "vmovntdqa 26*64(%[addr]),   %%zmm26 \n" \
    "vmovntdqa 27*64(%[addr]),   %%zmm27 \n" \
    "vmovntdqa 28*64(%[addr]),   %%zmm28 \n" \
    "vmovntdqa 29*64(%[addr]),   %%zmm29 \n" \
    "vmovntdqa 30*64(%[addr]),   %%zmm30 \n" \
    "vmovntdqa 31*64(%[addr]),   %%zmm31 \n"

#define WRITE_NT_2048_ASM \
    "vmovntdq   %%zmm0, 0*64(%[waddr]) \n" \
    "vmovntdq   %%zmm1, 1*64(%[waddr]) \n" \
    "vmovntdq   %%zmm2, 2*64(%[waddr]) \n" \
    "vmovntdq   %%zmm3, 3*64(%[waddr]) \n" \
    "vmovntdq   %%zmm4, 4*64(%[waddr]) \n" \
    "vmovntdq   %%zmm5, 5*64(%[waddr]) \n" \
    "vmovntdq   %%zmm6, 6*64(%[waddr]) \n" \
    "vmovntdq   %%zmm7, 7*64(%[waddr]) \n" \
    "vmovntdq   %%zmm8, 8*64(%[waddr]) \n" \
    "vmovntdq   %%zmm9, 9*64(%[waddr]) \n" \
    "vmovntdq  %%zmm10, 10*64(%[waddr]) \n" \
    "vmovntdq  %%zmm11, 11*64(%[waddr]) \n" \
    "vmovntdq  %%zmm12, 12*64(%[waddr]) \n" \
    "vmovntdq  %%zmm13, 13*64(%[waddr]) \n" \
    "vmovntdq  %%zmm14, 14*64(%[waddr]) \n" \
    "vmovntdq  %%zmm15, 15*64(%[waddr]) \n" \
    "vmovntdq   %%zmm16, 16*64(%[waddr]) \n" \
    "vmovntdq   %%zmm17, 17*64(%[waddr]) \n" \
    "vmovntdq   %%zmm18, 18*64(%[waddr]) \n" \
    "vmovntdq   %%zmm19, 19*64(%[waddr]) \n" \
    "vmovntdq   %%zmm20, 20*64(%[waddr]) \n" \
    "vmovntdq   %%zmm21, 21*64(%[waddr]) \n" \
    "vmovntdq   %%zmm22, 22*64(%[waddr]) \n" \
    "vmovntdq   %%zmm23, 23*64(%[waddr]) \n" \
    "vmovntdq   %%zmm24, 24*64(%[waddr]) \n" \
    "vmovntdq   %%zmm25, 25*64(%[waddr]) \n" \
    "vmovntdq  %%zmm26, 26*64(%[waddr]) \n" \
    "vmovntdq  %%zmm27, 27*64(%[waddr]) \n" \
    "vmovntdq  %%zmm28, 28*64(%[waddr]) \n" \
    "vmovntdq  %%zmm29, 29*64(%[waddr]) \n" \
    "vmovntdq  %%zmm30, 30*64(%[waddr]) \n" \
    "vmovntdq  %%zmm31, 31*64(%[waddr]) \n"

#define WRITE_NT_2048_ASM1 \
    "vmovntdq   %%zmm0, 0*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm1, 1*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm2, 2*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm3, 3*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm4, 4*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm5, 5*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm6, 6*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm7, 7*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm8, 8*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm9, 9*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm10, 10*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm11, 11*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm12, 12*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm13, 13*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm14, 14*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm15, 15*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm16, 16*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm17, 17*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm18, 18*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm19, 19*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm20, 20*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm21, 21*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm22, 22*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm23, 23*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm24, 24*64(%[waddr1]) \n" \
    "vmovntdq   %%zmm25, 25*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm26, 26*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm27, 27*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm28, 28*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm29, 29*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm30, 30*64(%[waddr1]) \n" \
    "vmovntdq  %%zmm31, 31*64(%[waddr1]) \n"


unsigned long avx_copy(void* dst1, void* dst2, void* src, size_t sz)
{
    unsigned long iters = sz / 2048;
    unsigned long i;
    void *dram_src, *dram_dst, *pmem_dst;

    if(!dst2)
        for(i = 0; i < iters; i++) {
            dram_src = src + (i << 11);
            pmem_dst = dst1 + (i << 11);
            asm volatile(
                READ_NT_2048_ASM
                WRITE_NT_2048_ASM
                : [addr] "+r" (dram_src), [waddr] "+r" (pmem_dst)
                : 
                : REGISTERS_2048
            );
        }
    else
        for(i = 0; i < iters; i++) {
            dram_src = src + (i << 11);
            pmem_dst = dst1 + (i << 11);
            dram_dst = dst2 + (i << 11);
            asm volatile(
                READ_NT_2048_ASM
                WRITE_NT_2048_ASM
                WRITE_NT_2048_ASM1
                : [addr] "+r" (dram_src), [waddr] "+r" (pmem_dst), [waddr1] "+r" (dram_dst)
                : 
                : REGISTERS_2048
            );
        }

    return 0;

}

