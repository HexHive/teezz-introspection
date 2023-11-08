#include <stdint.h>
#include <stdbool.h>
/*
 * Parsing should be able to handle all relevant primitive types.
 */

struct MyStruct
{
  int (*bytes)(uint8_t a, uint8_t b, uint8_t *c);
  int (*shorts)(uint16_t a, int16_t b, uint16_t *c);
  int (*ints)(uint32_t a, int b, int32_t c, int *d);
  int (*longs)(uint64_t a, long b, int64_t c, int64_t *d);
  int (*bools)(bool a, bool *b);
  // int (*floats)(float a, float *b);
  // int (*doubles)(double a, double *b);
};
