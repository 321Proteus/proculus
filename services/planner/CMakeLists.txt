add_library(planner_core STATIC src/planner.cpp)
target_include_directories(planner_core PUBLIC src)
target_link_libraries(planner_core PUBLIC proculus_netutil proculus_timing)

add_executable(planner src/main.cpp)
target_link_libraries(planner PRIVATE planner_core)

if(BUILD_TESTING)
	add_executable(test_planner tests/test_planner.cpp)
	target_link_libraries(test_planner PRIVATE planner_core)
	add_test(NAME planner COMMAND test_planner)
endif()
