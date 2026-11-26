# SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
# SPDX-License-Identifier: BSD-2-Clause

find_package(Qt6 ${QT_MIN_VERSION} CONFIG REQUIRED Test)

add_test(NAME kcm_smoketest COMMAND kcmshell6 --smoke-test kcm_krdpserver)
set_tests_properties(kcm_smoketest PROPERTIES
    ENVIRONMENT_MODIFICATION QT_PLUGIN_PATH=path_list_prepend:${CMAKE_BINARY_DIR}/bin
)

ecm_add_test(audiostreamtest.cpp
    TEST_NAME audiostreamtest
    LINK_LIBRARIES KRdp Qt6::Test Qt6::Network
)
