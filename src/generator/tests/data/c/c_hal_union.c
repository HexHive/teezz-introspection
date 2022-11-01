#include <stdio.h>
#include "c_hal_union.h"

int func_a(struct InternalStruct *a) {
  a->a = 10;
  a->b.u_c += 'a';
  a->c += 2;
  return 0;
}

int main() {
  struct MyStruct s;
  struct InternalStruct is;
  s.func_a = func_a;
  s.a.u_a = 'b';
  is.a = 1;
  is.b.u_a = 0x1122334455667788;
  is.c = 4;

  s.func_a(&is);

  printf("%d\n", is.a);
  return 0;
}
