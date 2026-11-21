add_library(scheduler_core STATIC src/schedule.cpp)
target_include_directories(scheduler_core PUBLIC src)

add_executable(scheduler src/main.cpp)
target_link_libraries(scheduler PRIVATE scheduler_core)

if(BUILD_TESTING)
	add_executable(test_schedule tests/test_schedule.cpp)
	target_link_libraries(test_schedule PRIVATE scheduler_core)
	add_test(NAME schedule COMMAND test_schedule)
endif()
