add_library(proculus_timing STATIC src/rate.cpp)
target_include_directories(proculus_timing PUBLIC include)

if(BUILD_TESTING)
	add_executable(test_rate tests/test_rate.cpp)
	target_link_libraries(test_rate PRIVATE proculus_timing)
	add_test(NAME timing_rate COMMAND test_rate)
endif()
