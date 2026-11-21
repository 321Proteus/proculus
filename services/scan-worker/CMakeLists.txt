find_package(EXPAT REQUIRED)

add_library(scanner_core STATIC
	src/nmap_xml.cpp
	src/process.cpp
	src/backend.cpp
	src/sim_network.cpp
	src/job.cpp
	src/result_json.cpp)
target_include_directories(scanner_core PUBLIC src)
target_link_libraries(scanner_core PUBLIC proculus_netutil EXPAT::EXPAT)

add_executable(scan-worker src/main.cpp)
target_link_libraries(scan-worker PRIVATE scanner_core)

if(BUILD_TESTING)
	add_executable(test_scan_worker tests/test_scan_worker.cpp)
	target_link_libraries(test_scan_worker PRIVATE scanner_core)
	add_test(NAME scan_worker COMMAND test_scan_worker)

	add_executable(test_sim tests/test_sim.cpp)
	target_link_libraries(test_sim PRIVATE scanner_core)
	add_test(NAME sim_network COMMAND test_sim)
endif()
