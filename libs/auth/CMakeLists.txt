# Users, roles and the audit log in Postgres. Only built when libs/db is (libpq + libsodium).
add_library(proculus_auth STATIC src/pgauth.cpp)
target_include_directories(proculus_auth PUBLIC include)
target_link_libraries(proculus_auth PUBLIC proculus_db proculus_web nlohmann_json::nlohmann_json)

if(BUILD_TESTING)
	# Needs a live Postgres: set PROCULUS_TEST_DB_URL, otherwise it is skipped.
	add_executable(test_pgauth tests/test_pgauth.cpp)
	target_link_libraries(test_pgauth PRIVATE proculus_auth)
	target_compile_definitions(test_pgauth PRIVATE PROCULUS_MIGRATIONS_DIR="${PROJECT_SOURCE_DIR}/db/migrations")
	add_test(NAME pgauth COMMAND test_pgauth)
	set_tests_properties(pgauth PROPERTIES SKIP_RETURN_CODE 77)
endif()
