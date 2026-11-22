add_library(proculus_web STATIC src/guard.cpp src/auth.cpp)
target_include_directories(proculus_web PUBLIC include)

if(BUILD_TESTING)
	add_executable(test_guard tests/test_guard.cpp)
	target_link_libraries(test_guard PRIVATE proculus_web)
	add_test(NAME web_guard COMMAND test_guard)

	add_executable(test_web_auth tests/test_auth.cpp)
	target_link_libraries(test_web_auth PRIVATE proculus_web)
	add_test(NAME web_auth COMMAND test_web_auth)
endif()
