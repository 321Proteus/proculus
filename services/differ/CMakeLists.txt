add_library(differ_core STATIC src/track.cpp src/compare.cpp src/report.cpp)
target_include_directories(differ_core PUBLIC src)
target_link_libraries(differ_core PUBLIC proculus_results proculus_netutil scheduler_core)

add_executable(differ src/main.cpp)
target_link_libraries(differ PRIVATE differ_core)

if(BUILD_TESTING)
	add_executable(test_track tests/test_track.cpp)
	target_link_libraries(test_track PRIVATE differ_core scanner_core) # scanner_core: the emulated network
	add_test(NAME differ_track COMMAND test_track)

	add_executable(test_compare tests/test_compare.cpp)
	target_link_libraries(test_compare PRIVATE differ_core)
	add_test(NAME differ_compare COMMAND test_compare)
endif()
