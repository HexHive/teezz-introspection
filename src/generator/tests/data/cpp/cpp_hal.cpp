#include "cpp_hal.hpp"
#include <iostream>

int foo::bar::baz::MyHAL::myfunc(int a, int b) {
  std::cout << (a+b) << std::endl;
  return 0;
}

int main () {
  foo::bar::baz::MyHAL m;
  m.myfunc(3,4);

  return 0;
}
