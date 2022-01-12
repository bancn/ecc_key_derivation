cmake_minimum_required(VERSION 3.20)
project(ecc C)
set(CMAKE_C_STANDARD 99)

include_directories(mbed/include)
aux_source_directory(${PROJECT_SOURCE_DIR}/mbed/library MBED_SRC)

set(src main.c utils.c utils.h ecc.c ecc.h)





add_executable(ecc ${src} ${MBED_SRC})
target_link_libraries(${PROJECT_NAME} ws2_32)