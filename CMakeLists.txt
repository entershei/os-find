cmake_minimum_required(VERSION 3.12)
project(os-find)

set(CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined")
#set(-D_GLIBCXX_DEBUG)

add_executable(find-utility find-utility.cpp)