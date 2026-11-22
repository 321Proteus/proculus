add_library(gateway_core STATIC src/demo.cpp src/api.cpp src/server.cpp src/scan_control.cpp src/token_guard.cpp)
target_include_directories(gateway_core PUBLIC src)
target_include_directories(gateway_core SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/httplib)
target_link_libraries(gateway_core PUBLIC planner_core scanner_core scheduler_core proculus_timing proculus_results proculus_insight proculus_web differ_core runner_core)
find_package(Threads REQUIRED)
target_link_libraries(gateway_core PUBLIC Threads::Threads)

add_executable(gateway src/main.cpp src/serve.cpp)
target_link_libraries(gateway PRIVATE gateway_core proculus_common)

if(BUILD_TESTING)
	add_executable(test_demo tests/test_demo.cpp)
	target_link_libraries(test_demo PRIVATE gateway_core)
	add_test(NAME demo COMMAND test_demo)

	add_executable(test_api tests/test_api.cpp)
	target_link_libraries(test_api PRIVATE gateway_core)
	add_test(NAME gateway_api COMMAND test_api)

	add_executable(test_scan_control tests/test_scan_control.cpp)
	target_link_libraries(test_scan_control PRIVATE gateway_core)
	add_test(NAME gateway_scan_control COMMAND test_scan_control)

	add_executable(test_server tests/test_server.cpp)
	target_link_libraries(test_server PRIVATE gateway_core)
	target_include_directories(test_server SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/httplib)
	add_test(NAME gateway_server COMMAND test_server)
endif()
