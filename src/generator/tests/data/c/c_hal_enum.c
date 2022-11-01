#include <stdio.h>
#include "c_hal_enum.h"

int myfunc_a (hal_enum a, int b) {
  printf("%i\n", b);
  return 0;
}

int main() {

  struct MyStruct s;
  s.myfunc_a = myfunc_a;

  s.myfunc_a(en_val_1, 2);
  s.myfunc_a(en_val_3, 4);
  s.myfunc_a(en_val_4, 6);

  return 0;
}
