cmake_minimum_required(VERSION 3.21)
project(opendrop-linux-owner-prompt LANGUAGES CXX)
find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
add_library(opendrop-linux-owner-prompt STATIC IncomingOfferDialog.cpp QtConsentBridge.cpp)
target_compile_features(opendrop-linux-owner-prompt PUBLIC cxx_std_17)
set_target_properties(opendrop-linux-owner-prompt PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(opendrop-linux-owner-prompt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(opendrop-linux-owner-prompt PUBLIC Qt6::Widgets PkgConfig::SYSTEMD)
# No network service, IPC or ticket issuer. This native library only presents
# the owner-facing modal UI and returns its result to the Rust core authority.

option(OPENDROP_BUILD_QT_TESTS "Build isolated hosted-only Qt dialog tests" OFF)
if(OPENDROP_BUILD_QT_TESTS)
    find_package(Qt6 REQUIRED COMPONENTS Test)
    enable_testing()
    add_executable(opendrop-qt-owner-dialog-test QtOwnerDialogTest.cpp)
    target_compile_features(opendrop-qt-owner-dialog-test PRIVATE cxx_std_17)
    target_link_libraries(opendrop-qt-owner-dialog-test PRIVATE
        opendrop-linux-owner-prompt Qt6::Test)
    add_test(NAME owner_dialog_event_boundary COMMAND opendrop-qt-owner-dialog-test)
    set_tests_properties(owner_dialog_event_boundary PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

    add_executable(opendrop-qt-foreground-lifecycle-test QtForegroundLifecycleTest.cpp)
    target_compile_features(opendrop-qt-foreground-lifecycle-test PRIVATE cxx_std_17)
    target_link_libraries(opendrop-qt-foreground-lifecycle-test PRIVATE
        opendrop-linux-owner-prompt Qt6::Test)
    add_test(NAME foreground_window_shutdown COMMAND opendrop-qt-foreground-lifecycle-test)
    set_tests_properties(foreground_window_shutdown PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
