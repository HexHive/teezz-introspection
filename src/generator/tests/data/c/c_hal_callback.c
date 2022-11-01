#include <stdio.h>
#include "c_hal_callback.h"

void callback(int a) {
  printf("%d\n", a);
}

int func_a (callback_func callback) {
  callback(3);
  return 0;
}

int main () {
  struct MyStruct s;
  s.func_a = func_a;

  s.func_a(callback);

  printf("Finished!\n");
  return 0;
}

