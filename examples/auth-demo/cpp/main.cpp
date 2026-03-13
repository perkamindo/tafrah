#include <iostream>
#include <stdexcept>

#include "../native/demo_core.hpp"

int main() {
  try {
    const auto result = tafrah_demo::run_demo();
    std::cout << tafrah_demo::result_to_json(result, "cpp") << std::endl;
    return result.ok ? 0 : 1;
  } catch (const std::exception& err) {
    std::cerr << "cpp demo failed: " << err.what() << std::endl;
    return 1;
  }
}
