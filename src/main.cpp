#include <exception>
#include <iostream>

#include "memory.hpp"

int main() {
  try {
    Process proc("notepad.exe");

    for (const auto &[key, value] : proc.modules()) {
      printf("Name: %s; address: %p\n", key.data(), value->address());

      // random pattern
      auto pattern = value->scanner().find_pattern<"xx">({0x85, 0x32});

      if (pattern.is_valid()) {
        printf("%llu\n", pattern.add(5).add(7).get());
      }
    }
  } catch (std::exception e) {
    std::cout << e.what() << std::endl;
  }

  return 0;
}