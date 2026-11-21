find_package(OpenSSL REQUIRED)

add_library(prober_core STATIC src/analyze.cpp)
target_include_directories(prober_core PUBLIC src)
target_link_libraries(prober_core PUBLIC proculus_netutil OpenSSL::SSL OpenSSL::Crypto)

if(BUILD_TESTING)
	add_executable(test_analyze tests/test_analyze.cpp)
	target_link_libraries(test_analyze PRIVATE prober_core)
	add_test(NAME http_analyze COMMAND test_analyze)
endif()
