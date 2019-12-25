add_executable(user user.cpp)
target_link_libraries(user ${OPENSSL_LIBRARIES} -pthread common sockpp)
set_target_properties(user PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")