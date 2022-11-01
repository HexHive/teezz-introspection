#include <iostream>
#include "cpp_hal_template.hpp"

int MyStruct::myfunc(MyTemplate<int> *a) {
  a->value = 5;
  return 0;
}

int main() {
  struct MyStruct ms;
  MyTemplate<int> mt;
  mt.value = 4;

  ms.myfunc(&mt);

  std::cout << mt.value << std::endl;
  return 0;
}
