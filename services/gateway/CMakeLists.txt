add_library(gateway_core STATIC src/demo.cpp src/api.cpp src/server.cpp src/scan_control.cpp src/token_guard.cpp src/reset_cli.cpp src/export_format.cpp src/simulate.cpp src/signature_store.cpp)
target_include_directories(gateway_core PUBLIC src)
target_include_directories(gateway_core SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/httplib)
target_link_libraries(gateway_core PUBLIC planner_core scanner_core scheduler_core proculus_timing proculus_results proculus_insight proculus_web proculus_edits differ_core runner_core)
find_package(Threads REQUIRED)
target_link_libraries(gateway_core PUBLIC Threads::Threads)

add_executable(gateway src/main.cpp src/serve.cpp)
target_link_libraries(gateway PRIVATE gateway_core ui_core proculus_common) # ui_core: `gateway serve` also serves the web UI
if(TARGET proculus_pgstore)
	target_link_libraries(gateway PRIVATE proculus_pgstore)
	target_compile_definitions(gateway PRIVATE PROCULUS_HAVE_PGSTORE)
endif()
if(TARGET proculus_auth AND TARGET proculus_pgstore)
	target_sources(gateway PRIVATE src/users_cli.cpp)
	target_link_libraries(gateway PRIVATE proculus_auth)
	target_compile_definitions(gateway PRIVATE PROCULUS_HAVE_AUTH)
endif()

if(BUILD_TESTING)
	add_executable(test_demo tests/test_demo.cpp)
	target_link_libraries(test_demo PRIVATE gateway_core)
	add_test(NAME demo COMMAND test_demo)

	add_executable(test_api tests/test_api.cpp)
	target_link_libraries(test_api PRIVATE gateway_core)
	add_test(NAME gateway_api COMMAND test_api)

	add_executable(test_export_format tests/test_export_format.cpp)
	target_link_libraries(test_export_format PRIVATE gateway_core)
	add_test(NAME gateway_export_format COMMAND test_export_format)

	add_executable(test_signature_store tests/test_signature_store.cpp)
	target_link_libraries(test_signature_store PRIVATE gateway_core)
	add_test(NAME gateway_signature_store COMMAND test_signature_store)

	add_executable(test_simulate tests/test_simulate.cpp)
	target_link_libraries(test_simulate PRIVATE gateway_core)
	target_compile_definitions(test_simulate PRIVATE PROCULUS_EXAMPLES_DIR="${PROJECT_SOURCE_DIR}/libs/signatures/examples")
	add_test(NAME gateway_simulate COMMAND test_simulate)

	add_executable(test_reset tests/test_reset.cpp)
	target_link_libraries(test_reset PRIVATE gateway_core)
	add_test(NAME gateway_reset COMMAND test_reset)

	add_executable(test_scan_control tests/test_scan_control.cpp)
	target_link_libraries(test_scan_control PRIVATE gateway_core)
	add_test(NAME gateway_scan_control COMMAND test_scan_control)

	add_executable(test_server_auth tests/test_server_auth.cpp)
	target_link_libraries(test_server_auth PRIVATE gateway_core)
	target_include_directories(test_server_auth SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/httplib)
	add_test(NAME gateway_server_auth COMMAND test_server_auth)

	add_executable(test_server tests/test_server.cpp)
	target_link_libraries(test_server PRIVATE gateway_core)
	target_include_directories(test_server SYSTEM PRIVATE ${PROJECT_SOURCE_DIR}/third_party/httplib)
	add_test(NAME gateway_server COMMAND test_server)
endif()
