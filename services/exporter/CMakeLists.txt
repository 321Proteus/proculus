add_library(exporter_core STATIC src/render.cpp)
target_include_directories(exporter_core PUBLIC src)
target_link_libraries(exporter_core PUBLIC proculus_results)

add_executable(exporter src/main.cpp)
target_link_libraries(exporter PRIVATE exporter_core)

if(BUILD_TESTING)
	add_executable(test_render tests/test_render.cpp)
	target_link_libraries(test_render PRIVATE exporter_core)
	add_test(NAME exporter_render COMMAND test_render)
endif()
