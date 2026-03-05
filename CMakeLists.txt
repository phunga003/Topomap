cmake_minimum_required(VERSION 3.10)
project(topomap C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# target binary - compiled static to be deployed to remote machines
add_executable(surveyor
    src/surveyor_main.c
    src/surveyor.c
    src/snapshot_io.c
)
target_include_directories(surveyor PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(surveyor -static -lpthread)

# scanner binary - runs locally, orchestrates scanning
add_executable(scan
    src/control_main.c
    src/snapshot_io.c
)
target_include_directories(scan PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(scan pthread)