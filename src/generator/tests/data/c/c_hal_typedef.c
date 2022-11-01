#include <stdio.h>
#include "c_hal_typedef.h"

int myfunc(SomeStruct_t *a, SomeStruct_t *b) {
  a->member_a = b->member_a;
  a->member_b = b->member_b;
  a->member_c = b->member_c;
  return 0;
}

int main() {
  struct MyStruct  mystruct;
  mystruct.myfunc = myfunc;

  SomeStruct_t a;
  a.member_a = 0;
  a.member_b = 0;
  a.member_c = 0;
  SomeStruct_t b;
  b.member_a = 2;
  b.member_b = 4;
  b.member_c = 8;

  mystruct.myfunc(&a, &b);

  printf("%d\n", a.member_a);

  return 0;
}
