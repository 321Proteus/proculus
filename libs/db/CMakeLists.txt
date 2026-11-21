# Needs libpq and libsodium. Locally they are optional (the library is skipped
# with a message); set -DPROCULUS_REQUIRE_DB=ON, as the Docker build does, to
# make a missing dependency a hard error.
find_package(PkgConfig QUIET)
find_package(PostgreSQL QUIET)
if(PkgConfig_FOUND)
	pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
endif()

if(NOT PostgreSQL_FOUND OR NOT SODIUM_FOUND)
	set(_missing "")
	if(NOT PostgreSQL_FOUND)
		string(APPEND _missing " libpq")
	endif()
	if(NOT SODIUM_FOUND)
		string(APPEND _missing " libsodium(+pkg-config)")
	endif()
	if(PROCULUS_REQUIRE_DB)
		message(FATAL_ERROR "libs/db: missing${_missing}")
	endif()
	message(STATUS "libs/db skipped: missing${_missing}")
	return()
endif()

add_library(proculus_db STATIC src/crypto.cpp src/connection.cpp src/migrate.cpp)
target_include_directories(proculus_db PUBLIC include)
target_link_libraries(proculus_db PUBLIC PostgreSQL::PostgreSQL PkgConfig::SODIUM)
set(PROCULUS_DB_ENABLED ON PARENT_SCOPE)

if(BUILD_TESTING)
	add_executable(test_crypto tests/test_crypto.cpp)
	target_link_libraries(test_crypto PRIVATE proculus_db)
	add_test(NAME db_crypto COMMAND test_crypto)

	# Needs a live Postgres: set PROCULUS_TEST_DB_URL, otherwise it is skipped.
	add_executable(test_db tests/test_db.cpp)
	target_link_libraries(test_db PRIVATE proculus_db)
	target_compile_definitions(test_db PRIVATE
		PROCULUS_MIGRATIONS_DIR="${PROJECT_SOURCE_DIR}/db/migrations")
	add_test(NAME db_integration COMMAND test_db)
	set_tests_properties(db_integration PROPERTIES SKIP_RETURN_CODE 77)
endif()
