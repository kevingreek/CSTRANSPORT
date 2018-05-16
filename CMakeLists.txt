cmake_minimum_required(VERSION 3.3)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules;${CMAKE_SOURCE_DIR}")

set(TARGET client)
SET (CMAKE_BUILD_TYPE "Debug")
# Either specify BOOST_ROOT or BOOST_INCLUDEDIR and BOOST_LIBRARYDIR.
# I am using "MinGW Distro" in this example, but also a relative path, e. g.
# "vendor/boost" can be specified.
set (BOOST_ROOT ${BOOST_ROOT})
set (Boost_NO_SYSTEM_PATHS ON)
set (Boost_USE_MULTITHREADED ON)
set (Boost_USE_STATIC_LIBS ON)
set (Boost_USE_STATIC_RUNTIME OFF)
set (BOOST_ALL_DYN_LINK OFF)
set(CMAKE_CXX14_EXTENSION_COMPILE_OPTION -std=c++14)
set(CMAKE_CXX_STANDARD 14)
#message (STATUS "MSVC: " ${BOOST_ROOT} )

# Load settings for the external project "Boost".
# The components "system" and "filesystem" from "Boost" version 1.66.0 or
# greater are required.
find_package (Boost 1.66.0 REQUIRED COMPONENTS system filesystem)
if (Boost_FOUND)
  # From the offical documentation:
  # Add include directories to the build. [...] If the SYSTEM option is given,
  # the compiler will be told the directories are meant as system include
  # directories on some platforms (signalling this setting might achieve effects
  # such as the compiler skipping warnings [...])."
  include_directories (SYSTEM ${Boost_INCLUDE_DIR})

  # From the offical documentation:
  # "Specify directories in which the linker will look for libraries. [...] Note
  # that this command is rarely necessary. Library locations returned by
  # find_package() and find_library() are absolute paths. Pass these absolute
  # library file paths directly to the target_link_libraries() command. CMake
  # will ensure the linker finds them."
  link_directories (${Boost_LIBRARY_DIRS})
endif ()

# enable all warning
#add_definitions(/W4)

#enable warning as error
#if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
#	add_definitions(/WX)
#elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
#	add_definitions(/Werror)
#endif()


include_directories (${PROJECT_SOURCE_DECLARATION_DIRECTORY})
add_executable(${TARGET} 	main.cpp
							SessionIO.cpp
							sha1.cpp
							TextHelp.cpp
							SessionIO.hpp
							sha1.hpp
							TextHelp.hpp
							Export_Config.h
							)
target_compile_features(${TARGET} PUBLIC cxx_std_11)

