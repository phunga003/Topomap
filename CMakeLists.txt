cmake_minimum_required(VERSION 3.10)
project(surveyor C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# target binary - static, deployed to remote machines
add_executable(surveyor
    src/surveyor_main.c
    src/surveyor.c
    src/hashmap.c
    src/snapshot_io.c
)
target_include_directories(surveyor PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(surveyor -static -lpthread)

# control plane binary
add_executable(control
    src/control_main.c
    src/commands.c
    src/command_engine.c
    src/command_utils.c
    src/session.c
    src/scanner.c
    src/snapshot_io.c
    src/hashmap.c
    src/map.c
    src/diff.c
)
target_include_directories(control PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(control pthread)