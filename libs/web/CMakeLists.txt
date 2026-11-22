add_library(proculus_web STATIC src/guard.cpp)
target_include_directories(proculus_web PUBLIC include)

if(BUILD_TESTING)
	add_executable(test_guard tests/test_guard.cpp)
	target_link_libraries(test_guard PRIVATE proculus_web)
	add_test(NAME web_guard COMMAND test_guard)
endif()
