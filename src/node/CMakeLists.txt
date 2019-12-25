add_executable(node node.cpp)
target_link_libraries(node ${OPENSSL_LIBRARIES} -pthread common sockpp ${LEVELDB_LIBRARIES})
set_target_properties(node PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}")