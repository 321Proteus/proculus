# User edits of scanned data (kept apart from the scans, so no scan can overwrite them).
add_library(proculus_edits STATIC src/edits.cpp)
target_include_directories(proculus_edits PUBLIC include)
target_link_libraries(proculus_edits PUBLIC nlohmann_json::nlohmann_json)

if(BUILD_TESTING)
	add_executable(test_edits tests/test_edits.cpp)
	target_link_libraries(test_edits PRIVATE proculus_edits)
	add_test(NAME edits COMMAND test_edits)
endif()
