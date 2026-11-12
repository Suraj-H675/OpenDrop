cmake_minimum_required(VERSION 3.21)
project(opendrop-share-handoff LANGUAGES CXX)
find_package(Qt6 REQUIRED COMPONENTS Core DBus)
add_executable(opendrop-share opendrop-share.cpp)
target_compile_features(opendrop-share PRIVATE cxx_std_17)
target_link_libraries(opendrop-share PRIVATE Qt6::Core Qt6::DBus)
# Deliberately no install() call. Device/desktop registration is a separate
# owner-authorized real-GUI acceptance gate.
