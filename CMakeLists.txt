cmake_minimum_required(VERSION 3.16)
project(forgeops_tracker C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)

add_library(forgeops_tracker
    src/configuration.c
    src/pii_scrubber.c
    src/event_builder.c
    src/crash_store.c
    src/client.c
    src/signal_handler.c
    src/reporter.c
    src/forgeops_tracker.c
)
target_include_directories(forgeops_tracker PUBLIC include)
target_link_libraries(forgeops_tracker PUBLIC CURL::libcurl)
# Real (not stub) backtrace symbol resolution needs frame pointers and debug info -- without
# -fno-omit-frame-pointer, backtrace() can silently return far fewer/wrong frames under
# optimization, which would make event_builder's own tests flaky depending on build type.
target_compile_options(forgeops_tracker PRIVATE -g -fno-omit-frame-pointer -Wall -Wextra)

enable_testing()
add_executable(forgeops_tracker_tests tests/test_forgeops_tracker.c)
target_link_libraries(forgeops_tracker_tests PRIVATE forgeops_tracker)
target_compile_options(forgeops_tracker_tests PRIVATE -g -fno-omit-frame-pointer -Wall -Wextra)
add_test(NAME forgeops_tracker_tests COMMAND forgeops_tracker_tests)
