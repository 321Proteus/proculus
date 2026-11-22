# A Postgres-backed ResultStore. Only built when libs/db is (libpq + libsodium).
add_library(proculus_pgstore STATIC src/pgstore.cpp src/pgedits.cpp)
target_include_directories(proculus_pgstore PUBLIC include)
target_link_libraries(proculus_pgstore PUBLIC proculus_db proculus_results proculus_edits)
target_compile_definitions(proculus_pgstore PRIVATE PROCULUS_DEFAULT_MIGRATIONS_DIR="${PROJECT_SOURCE_DIR}/db/migrations")

if(BUILD_TESTING)
	# Needs a live Postgres: set PROCULUS_TEST_DB_URL, otherwise it is skipped.
	add_executable(test_pgstore tests/test_pgstore.cpp)
	target_link_libraries(test_pgstore PRIVATE proculus_pgstore)
	target_compile_definitions(test_pgstore PRIVATE PROCULUS_MIGRATIONS_DIR="${PROJECT_SOURCE_DIR}/db/migrations")
	add_test(NAME pgstore COMMAND test_pgstore)
	set_tests_properties(pgstore PROPERTIES SKIP_RETURN_CODE 77)

	add_executable(test_pgedits tests/test_pgedits.cpp)
	target_link_libraries(test_pgedits PRIVATE proculus_pgstore)
	target_compile_definitions(test_pgedits PRIVATE PROCULUS_MIGRATIONS_DIR="${PROJECT_SOURCE_DIR}/db/migrations")
	add_test(NAME pgedits COMMAND test_pgedits)
	set_tests_properties(pgedits PROPERTIES SKIP_RETURN_CODE 77)
endif()
