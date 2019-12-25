add_executable(service service.cpp)
target_link_libraries(service ${OPENSSL_LIBRARIES} -pthread common sockpp)
set_target_properties(service PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")