add_library(common STATIC crypto.hpp base64.hpp base64.cpp)
set_target_properties(common PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")