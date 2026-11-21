add_library(proculus_results STATIC src/results.cpp)
target_include_directories(proculus_results PUBLIC include)
target_link_libraries(proculus_results PUBLIC nlohmann_json::nlohmann_json)

if(BUILD_TESTING)
	add_executable(test_results tests/test_results.cpp)
	target_link_libraries(test_results PRIVATE proculus_results)
	add_test(NAME results COMMAND test_results)
endif()
