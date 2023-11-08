#include <iostream>
#include "cpp_hal_enum.hpp"

int MyHAL::myfunc(enum_hal en_val, long b) {
  if (en_val == en_val_1) {
    return b;
  }
  return b + 1;
}

int main () {
  MyHAL m;

  std::cout << m.myfunc(en_val_1, 5) << std::endl;
  std::cout << m.myfunc(en_val_4, 5) << std::endl;
  return 0;
}
