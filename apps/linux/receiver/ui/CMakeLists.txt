cmake_minimum_required(VERSION 3.21)
project(opendrop-linux-owner-prompt LANGUAGES CXX)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
add_library(opendrop-linux-owner-prompt STATIC IncomingOfferDialog.cpp)
target_compile_features(opendrop-linux-owner-prompt PUBLIC cxx_std_17)
target_include_directories(opendrop-linux-owner-prompt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(opendrop-linux-owner-prompt PUBLIC Qt6::Widgets)
# No executable, install rule, DBus service, IPC handler or consent issuer.
# A reviewed in-process Qt/Rust bridge must privately bind the actual UI
# event and approved directory to the core's exact session/offer token.
