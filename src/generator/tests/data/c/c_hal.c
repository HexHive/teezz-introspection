#include <stdio.h>
#include "c_hal.h"

int myfunc(int a, int b) {
  return a+b;
}

int main(){

  struct mystruct s;
  s.myfunc = myfunc;

  printf("%d\n", s.myfunc(3, 4));

  return 0;
}
