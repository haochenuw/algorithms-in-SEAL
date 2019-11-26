# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)

project(EXAMPLES VERSION 3.4.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${EXAMPLES_SOURCE_DIR}/bin)

add_executable(polyeval polyeval_main.cpp)
target_sources(polyeval
    PRIVATE
	   7_polyeval.cpp
)

add_executable(mvproduct mvproduct_main.cpp)
target_sources(mvproduct
	PRIVATE
	mvproduct.cpp
)


# Import Microsoft SEAL
find_package(SEAL 3.4.0 EXACT REQUIRED
    # Providing a path so this can be built without installing Microsoft SEAL
    # PATHS ${SEALExamples_SOURCE_DIR}/../src/cmake
)

# Link Microsoft SEAL
target_link_libraries(polyeval SEAL::seal)

target_link_libraries(mvproduct SEAL::seal)
