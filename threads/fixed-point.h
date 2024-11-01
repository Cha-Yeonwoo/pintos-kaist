#ifndef FIXED_POINT_H
#define FIXED_POINT_H
#define fp_fr 14
#define fp_f (1 << 14)
#define FP(x) ((x) << 14)
#define FP2INT(x) ((x) >> 14)
#define MUL(x, y) (((int64_t)(x)) * (y) / (fp_f))
#define DIV(x, y) (((int64_t)(x)) * (fp_f) / (y))
typedef int32_t FP;
#endif