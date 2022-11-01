#include <stdio.h>
#include "c_hal_array.h"

int func_a(struct MyStruct *dev, struct InnerStruct *a, struct InnerStruct *b) {
  int temp_i[4];
  long temp_l[6];

  for (int i = 0; i < 4; ++i) {
    temp_i[i] = b->a[i];
    b->a[i] = a->a[i];
    temp_l[i] = b->b[i];
    b->b[i] = a->b[i];
    a->a[i] = temp_i[i];
    a->b[i] = temp_l[i];
  }

  for (int i = 4; i < 6; ++i) {
    temp_l[i] = b->b[i];
    b->b[i] = a->b[i];
    a->b[i] = temp_l[i];
  }
  return 0;
}

int main () {
  struct InnerStruct a = {{1,2,3,4},{5,6,7,8,9,10}};
  struct InnerStruct b = {{10,9,8,7},{6,5,4,3,2,1}};
  struct MyStruct s;
  s.func_a = func_a;

  s.func_a(&s, &a, &b);

  printf("%d\n", a.a[3]);
  return 0;
}
