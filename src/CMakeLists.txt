cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(live_moni)

find_library(TINS_LIBRARY tins)
set(SOURCE_FILES main.cpp)
#[[IMPORTANT

#If you get compile errors regarding regex, manually force a newer g++ version if necessary. 4.9 or newer should not pose problems.

Line would be for example:
set(CMAKE_CXX_COMPILER /usr/bin/g++-4.9)


]]

LINK_DIRECTORIES(${LINK_DIRECTORIES})
add_executable(live_moni ${SOURCE_FILES})
target_link_libraries(live_moni -pthread ${TINS_LIBRARY})
