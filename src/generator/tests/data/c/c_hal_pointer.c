#include <stdio.h>
#include "c_hal_pointer.h"

int func_a(struct MyStruct *dev, int *a) {
  *a = 4;
  return 0;
}

int func_b(struct MyStruct *dev, int **b) {
  printf("%d\n", **b);
  return 0;
}

int func_c(struct MyStruct *dev, struct InternalStruct *a) {
  **(a->b) = (short) *(a->a);
  *(a->a) = 16;
  return 0;
}

int main () {
  struct MyStruct s;
  s.func_a = func_a;
  s.func_b = func_b;
  s.func_c = func_c;

  int my_int = 2;
  int *p_my_int = &my_int;
  long internal_s_a = 5;
  short sh = 4;
  short *internal_s_b = &sh;
  struct InternalStruct internal_s;
  internal_s.a = &internal_s_a;
  internal_s.b = &internal_s_b;

  s.func_a(&s, &my_int);
  s.func_b(&s, &p_my_int);
  s.func_c(&s, &internal_s);

  printf("%ld\n", *(internal_s.a));
  return 0;
}
