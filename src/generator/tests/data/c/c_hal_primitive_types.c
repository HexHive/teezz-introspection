#include <stdio.h>
#include "c_hal_primitive_types.h"

int bytes(uint8_t a, uint8_t b, uint8_t *c)
{
  *c = a + b;
  return 0;
}

int shorts(uint16_t a, int16_t b, uint16_t *c)
{
  *c = a + b;
  return 0;
}

int ints(uint32_t a, int b, int32_t c, int *d)
{
  *d = a + b + c;
  return 0;
}

int longs(uint64_t a, long b, int64_t c, int64_t *d)
{
  *d = a + b + c;
  return 0;
}

int bools(bool a, bool *b)
{
  *b = a;
  return 0;
}

int floats(float a, float *b)
{
  *b = a;
  return 0;
}

int doubles(double a, double *b)
{
  *b = a;
  return 0;
}

int main()
{
  struct MyStruct s;
  s.bytes = bytes;
  s.shorts = shorts;
  s.ints = ints;
  s.longs = longs;
  // s.floats = floats;
  // s.doubles = doubles;
  s.bools = bools;

  char bytes_c = 0;
  uint16_t shorts_c = 0;
  int ints_d = 0;
  int64_t longs_d = 0;
  bool bools_b = 0;
  float floats_b = 0.0f;
  double doubles_b = 0.0;

  s.bytes(0xa, 1, &bytes_c);
  s.shorts(1, 2, &shorts_c);
  s.ints(3, 4, 5, &ints_d);
  s.longs(6, 7, 8, &longs_d);
  s.bools(true, &bools_b);
  // s.floats(3.4f, &floats_b);
  // s.doubles(5.6, &doubles_b);

  printf("%d\n", ints_d);

  return 0;
}
