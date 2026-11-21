add_library(gateway_core STATIC src/demo.cpp)
target_include_directories(gateway_core PUBLIC src)
target_link_libraries(gateway_core PUBLIC planner_core scanner_core scheduler_core proculus_timing proculus_results)

add_executable(gateway src/main.cpp)
target_link_libraries(gateway PRIVATE gateway_core proculus_common)

if(BUILD_TESTING)
	add_executable(test_demo tests/test_demo.cpp)
	target_link_libraries(test_demo PRIVATE gateway_core)
	add_test(NAME demo COMMAND test_demo)
endif()
