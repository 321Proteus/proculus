add_library(proculus_insight STATIC src/interest.cpp src/dashboard.cpp)
target_include_directories(proculus_insight PUBLIC include)
target_link_libraries(proculus_insight PUBLIC proculus_results differ_core proculus_netutil)

if(BUILD_TESTING)
	add_executable(test_insight tests/test_insight.cpp)
	target_link_libraries(test_insight PRIVATE proculus_insight)
	add_test(NAME insight COMMAND test_insight)
endif()
