# SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
# SPDX-License-Identifier: BSD-2-Clause

find_package(Qt6 ${QT_MIN_VERSION} CONFIG REQUIRED Test)

add_test(NAME kcm_smoketest COMMAND kcmshell6 --smoke-test kcm_krdpserver)
set_tests_properties(kcm_smoketest PROPERTIES
    ENVIRONMENT_MODIFICATION QT_PLUGIN_PATH=path_list_prepend:${CMAKE_BINARY_DIR}/bin
)

ecm_add_test(vsocktransporttest.cpp
    TEST_NAME vsocktransporttest
    LINK_LIBRARIES KRdp Qt6::Test Qt6::Network
)

ecm_add_test(videostreamqualitytest.cpp
    TEST_NAME videostreamqualitytest
    LINK_LIBRARIES KRdp Qt6::Test Qt6::Gui Qt6::Network
)

ecm_add_test(vmconnectauthtest.cpp
    ../src/RdpConnection.cpp
    ../src/PeerContext.cpp
    ../src/NetworkDetection.cpp
    ${CMAKE_BINARY_DIR}/src/krdp_logging.cpp
    TEST_NAME vmconnectauthtest
    LINK_LIBRARIES KRdp Qt6::Test Qt6::Network Qt6::Gui
)
target_include_directories(vmconnectauthtest PRIVATE ${CMAKE_BINARY_DIR}/src ${CMAKE_SOURCE_DIR}/src)
target_compile_definitions(vmconnectauthtest PRIVATE KRDP_VMCONNECT_TEST_HARNESS KRDP_STATIC_DEFINE)
