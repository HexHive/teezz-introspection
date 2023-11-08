#include <stdio.h>
#include "c_hal_complex.h"

int myfuncptr(struct ComplexStruct *a, struct WrapperStruct *b) {
  return a->member_a + b->test;
}

int myfuncptr2(struct WrapperStruct *a, struct InnerStruct *b) {
  return a->cs.member_a - b->inner_member_a;
}


int main() {
  struct MyStruct s;
  s.myfuncptr = myfuncptr;
  s.myfuncptr2 = myfuncptr2;

  struct WrapperStruct w;
  struct ComplexStruct c;
  struct InnerStruct i;
  i.inner_member_a = 4;
  i.inner_member_b = 6;
  i.inner_member_c = 8;

  c.is = i;
  c.member_a = 16;

  w.cs = c;
  w.test = 24;

  printf("%d\n", s.myfuncptr(&c, &w));
  printf("%d\n", s.myfuncptr2(&w, &i));

  return 0;
}
