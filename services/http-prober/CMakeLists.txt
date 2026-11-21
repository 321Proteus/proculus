find_package(OpenSSL REQUIRED)

add_library(prober_core STATIC src/analyze.cpp src/tls_cert.cpp src/socket_transport.cpp src/prober.cpp)
target_include_directories(prober_core PUBLIC src)
target_link_libraries(prober_core PUBLIC proculus_netutil OpenSSL::SSL OpenSSL::Crypto)
find_package(Threads REQUIRED)
target_link_libraries(prober_core PUBLIC Threads::Threads)

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
endif()
