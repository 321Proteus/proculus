find_package(OpenSSL REQUIRED)

add_library(prober_core STATIC src/analyze.cpp src/tls_cert.cpp src/socket_transport.cpp src/prober.cpp src/report.cpp src/evidence.cpp src/web_record.cpp)
target_include_directories(prober_core PUBLIC src)
target_link_libraries(prober_core PUBLIC proculus_netutil proculus_sig proculus_results nlohmann_json::nlohmann_json OpenSSL::SSL OpenSSL::Crypto)
find_package(Threads REQUIRED)
target_link_libraries(prober_core PUBLIC Threads::Threads)

add_executable(http-prober src/main.cpp)
target_link_libraries(http-prober PRIVATE prober_core proculus_results)

if(BUILD_TESTING)
	add_executable(test_analyze tests/test_analyze.cpp)
	target_link_libraries(test_analyze PRIVATE prober_core)
	add_test(NAME http_analyze COMMAND test_analyze)

	add_executable(test_socket tests/test_socket.cpp)
	target_link_libraries(test_socket PRIVATE prober_core)
	add_test(NAME http_socket COMMAND test_socket)

	add_executable(test_prober tests/test_prober.cpp)
	target_link_libraries(test_prober PRIVATE prober_core)
	add_test(NAME http_prober COMMAND test_prober)

	add_executable(test_evidence tests/test_evidence.cpp)
	target_link_libraries(test_evidence PRIVATE prober_core)
	add_test(NAME http_evidence COMMAND test_evidence)

	add_executable(test_web_record tests/test_web_record.cpp)
	target_link_libraries(test_web_record PRIVATE prober_core)
	add_test(NAME http_web_record COMMAND test_web_record)

	add_executable(test_report tests/test_report.cpp)
	target_link_libraries(test_report PRIVATE prober_core)
	add_test(NAME http_report COMMAND test_report)
endif()
