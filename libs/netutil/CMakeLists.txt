add_library(proculus_netutil STATIC src/cidr.c)
target_include_directories(proculus_netutil PUBLIC include)

if(BUILD_TESTING)
	add_executable(test_cidr tests/test_cidr.c)
	target_link_libraries(test_cidr PRIVATE proculus_netutil)
	add_test(NAME cidr COMMAND test_cidr)
endif()
