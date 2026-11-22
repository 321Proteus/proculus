add_library(signatures_core STATIC src/commands.cpp)
target_include_directories(signatures_core PUBLIC src)
target_link_libraries(signatures_core PUBLIC proculus_sig)

add_executable(signatures src/main.cpp)
target_link_libraries(signatures PRIVATE signatures_core)

if(BUILD_TESTING)
	add_executable(test_signatures_cli tests/test_commands.cpp)
	target_link_libraries(test_signatures_cli PRIVATE signatures_core)
	add_test(NAME signatures_cli COMMAND test_signatures_cli)
	# the documented example must stay valid
	add_test(NAME signatures_example_lint COMMAND signatures lint ${PROJECT_SOURCE_DIR}/libs/signatures/examples/custom.json)
endif()
