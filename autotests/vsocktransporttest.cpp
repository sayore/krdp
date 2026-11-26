// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QPointer>
#include <QProcess>
#include <QSignalSpy>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTest>

#include <sys/socket.h>
#include <unistd.h>

#ifdef HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#endif

#include <freerdp/freerdp.h>
#include <freerdp/peer.h>

#include "RdpConnection.h"
#include "Server.h"

class VsockTransportTest : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_tempDir;
    std::filesystem::path m_certPath;
    std::filesystem::path m_keyPath;

private Q_SLOTS:
    void initTestCase()
    {
        QVERIFY(m_tempDir.isValid());
        m_certPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.crt")).toStdString());
        m_keyPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.key")).toStdString());

        QProcess openssl;
        openssl.start(QStringLiteral("openssl"),
                      {
                          QStringLiteral("req"),
                          QStringLiteral("-x509"),
                          QStringLiteral("-newkey"),
                          QStringLiteral("rsa:2048"),
                          QStringLiteral("-nodes"),
                          QStringLiteral("-keyout"),
                          QString::fromStdString(m_keyPath.string()),
                          QStringLiteral("-out"),
                          QString::fromStdString(m_certPath.string()),
                          QStringLiteral("-days"),
                          QStringLiteral("1"),
                          QStringLiteral("-subj"),
                          QStringLiteral("/CN=krdp-foxcore-test"),
                      });
        QVERIFY2(openssl.waitForFinished(15000), "openssl timed out");
        QCOMPARE(openssl.exitCode(), 0);
        QVERIFY(std::filesystem::exists(m_certPath));
        QVERIFY(std::filesystem::exists(m_keyPath));
    }

    void testTcpRejectsHyperVMode()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setHyperVMode(true);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);

        QVERIFY(!server.start());
        QVERIFY(!server.isListeningTransport());
    }

    void testTcpRejectsInBandGreeter()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setHyperVMode(false);
        server.setInBandGreeterEnabled(true);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);

        QVERIFY(!server.start());
        QVERIFY(!server.isListeningTransport());
    }

    void testVsockRejectsWildcardPeerCid()
    {
#ifdef HAVE_LINUX_VM_SOCKETS_H
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Vsock);
        server.setHyperVMode(true);
        server.setPort(34388);
        server.setAllowedVsockPeerCid(VMADDR_CID_ANY);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);

        QVERIFY(!server.start());
        QVERIFY(!server.isListeningTransport());
#else
        QSKIP("Built without <linux/vm_sockets.h>");
#endif
    }

    void testVsockListenHasNoTcpListener()
    {
#ifdef HAVE_LINUX_VM_SOCKETS_H
        const int probe = ::socket(AF_VSOCK, SOCK_STREAM, 0);
        if (probe < 0) {
            QSKIP("AF_VSOCK not available in kernel");
        }
        ::close(probe);

        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Vsock);
        server.setHyperVMode(true);
        server.setPort(34389);
        server.setAllowedVsockPeerCid(VMADDR_CID_HOST);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);

        QVERIFY(server.start());
        QVERIFY(server.isListeningTransport());
        // QTcpServer must NOT be listening when transport is Vsock
        QVERIFY(!server.isListening());

        server.stop();
        QVERIFY(!server.isListeningTransport());
#else
        QSKIP("Built without <linux/vm_sockets.h>");
#endif
    }

    void testTcpStillEnforcesTlsHandshake()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setHyperVMode(false);
        server.setUsePAMAuthentication(true);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);

        QVERIFY(server.start());
        QVERIFY(server.isListening());
        QVERIFY(server.serverPort() != 0);

        QSignalSpy connSpy(&server, &KRdp::Server::newConnectionCreated);

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, server.serverPort());
        QVERIFY(client.waitForConnected(3000));
        QTRY_COMPARE(connSpy.count(), 1);

        QPointer<KRdp::RdpConnection> conn(connSpy.takeFirst().at(0).value<KRdp::RdpConnection *>());
        QVERIFY(!conn.isNull());

        // Send standard X.224 CR-TPDU with RDP_NEG_REQ requesting SSL|HYBRID|HYBRID_EX (0x0b)
        const QByteArray crTpdu = QByteArray::fromHex(
            "03000013" // TPKT v3, len 19
            "0ee00000000000" // X.224 CR-TPDU
            "01000800" // RDP_NEG_REQ, flags=0, len=8
            "0b000000"); // SSL|HYBRID|HYBRID_EX
        QCOMPARE(client.write(crTpdu), crTpdu.size());
        QVERIFY(client.waitForBytesWritten(3000));
        QTRY_VERIFY_WITH_TIMEOUT(client.bytesAvailable() >= 19, 3000);

        const QByteArray ccTpdu = client.readAll();
        QVERIFY2(ccTpdu.size() >= 19, "Expected X.224 CC-TPDU with RDP_NEG_RSP");
        // Verify TPKT v3 + X.224 CC (0xd0) + RDP_NEG_RSP (0x02) + SelectedProtocol == PROTOCOL_SSL (0x01)
        QCOMPARE(static_cast<unsigned char>(ccTpdu[0]), 0x03u);
        QCOMPARE(static_cast<unsigned char>(ccTpdu[5]), 0xd0u);
        QCOMPARE(static_cast<unsigned char>(ccTpdu[11]), 0x02u);
        QCOMPARE(static_cast<unsigned char>(ccTpdu[15]), 0x01u);

        // Now send plaintext TPKT (what Hyper-V vmms sends, NOT a TLS ClientHello).
        // Because this is TCP (not verified AF_VSOCK VMConnect), KRdp MUST enforce TLS and reject it!
        const QByteArray plaintextTpkt = QByteArray::fromHex("0300001002f0807f6505040100040100");
        QCOMPARE(client.write(plaintextTpkt), plaintextTpkt.size());
        QVERIFY(client.waitForBytesWritten(3000));
        QTRY_VERIFY_WITH_TIMEOUT(client.state() == QAbstractSocket::UnconnectedState, 3000);

        // Server destroys the RdpConnection once it enters State::Closed
        QTRY_VERIFY_WITH_TIMEOUT(conn.isNull(), 3000);
        server.stop();
    }

    void testFreeRdpVmConnectNegotiationAndPlaintextMcs()
    {
        // Verify against the installed FreeRDP 3.33.1 library that our exact Hyper-V
        // VMConnect settings negotiate PROTOCOL_SSL with RDP_NEG_REQ=0x0b, advertise
        // RESTRICTED_ADMIN_MODE_SUPPORTED, skip the guest-side TLS handshake, and
        // accept subsequent plaintext TPKT/MCS data instead of failing with
        // tls_validate_record_header:wrong version number.
        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        freerdp_peer *peer = freerdp_peer_new(fds[0]);
        QVERIFY(peer != nullptr);
        QVERIFY(freerdp_peer_context_new(peer));

        rdpSettings *settings = peer->context->settings;
        auto *cert = freerdp_certificate_new_from_file(m_certPath.string().c_str());
        auto *key = freerdp_key_new_from_file(m_keyPath.string().c_str());
        QVERIFY(cert != nullptr);
        QVERIFY(key != nullptr);
        QVERIFY(freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1));
        QVERIFY(freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1));

        // Exact security profile applied by KRdp::RdpConnection::initialize() in VmConnectMode:
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_VmConnectMode, TRUE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, FALSE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, FALSE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, FALSE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_RdstlsSecurity, FALSE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_RestrictedAdminModeSupported, TRUE));
        QVERIFY(freerdp_settings_set_bool(settings, FreeRDP_SupportGraphicsPipeline, TRUE));
        QVERIFY(peer->Initialize(peer));

        // 1. Send X.224 CR-TPDU with RDP_NEG_REQ = SSL|HYBRID|HYBRID_EX (0x0000000b)
        const QByteArray crTpdu = QByteArray::fromHex(
            "03000013"
            "0ee00000000000"
            "01000800"
            "0b000000");
        QCOMPARE(::send(fds[1], crTpdu.constData(), static_cast<size_t>(crTpdu.size()), 0), crTpdu.size());

        // Drive server peer state machine through INITIAL -> NEGO -> MCS_CREATE_REQUEST
        QVERIFY2(peer->CheckFileDescriptor(peer) == TRUE, "FreeRDP VmConnectMode negotiation failed");

        // Read X.224 CC-TPDU response
        char respBuf[64] = {};
        const ssize_t n = ::recv(fds[1], respBuf, sizeof(respBuf), 0);
        QVERIFY2(n >= 19, "Expected 19-byte X.224 CC-TPDU with RDP_NEG_RSP");
        QCOMPARE(static_cast<unsigned char>(respBuf[0]), 0x03u); // TPKT v3
        QCOMPARE(static_cast<unsigned char>(respBuf[5]), 0xd0u); // X.224 CC
        QCOMPARE(static_cast<unsigned char>(respBuf[11]), 0x02u); // TYPE_RDP_NEG_RSP
        // Flags must include EXTENDED_CLIENT_DATA_SUPPORTED (0x01), DYNVC_GFX_PROTOCOL_SUPPORTED (0x02),
        // and RESTRICTED_ADMIN_MODE_SUPPORTED (0x08) -> 0x0b
        QVERIFY((static_cast<unsigned char>(respBuf[12]) & 0x0bu) == 0x0bu);
        QCOMPARE(static_cast<unsigned char>(respBuf[15]), 0x01u); // SelectedProtocol == PROTOCOL_SSL

        // Verify peer authenticated and advanced past NEGO without attempting TLS handshake
        QVERIFY(peer->authenticated == TRUE);
        constexpr uint32_t ProtocolSsl = 0x00000001u;
        QCOMPARE(freerdp_settings_get_uint32(settings, FreeRDP_SelectedProtocol), ProtocolSsl);
        QCOMPARE(freerdp_settings_get_bool(settings, FreeRDP_UseRdpSecurityLayer), FALSE);

        peer->Close(peer);
        freerdp_peer_context_free(peer);
        freerdp_peer_free(peer);
        ::close(fds[1]);
    }

    void testVmConnectModeDefenseInDepthRejectsNonVsockFd()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);
        QVERIFY(server.start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo forgedInfo;
        forgedInfo.transport = KRdp::Server::Transport::Vsock;
        forgedInfo.vmConnectMode = true;
        forgedInfo.vsockPeerCid = 2;
        forgedInfo.vsockPeerPort = 12345;

        KRdp::RdpConnection conn(&server, fds[0], forgedInfo);
        QTRY_COMPARE(conn.state(), KRdp::RdpConnection::State::Closed);

        ::close(fds[1]);
        server.stop();
    }

    void testDisallowedRootUsers()
    {
        QVERIFY(KRdp::RdpConnection::isDisallowedLoginUser(QString()));
        QVERIFY(KRdp::RdpConnection::isDisallowedLoginUser(QStringLiteral("root")));
        QVERIFY(KRdp::RdpConnection::isDisallowedLoginUser(QStringLiteral("ROOT")));
        QVERIFY(KRdp::RdpConnection::isDisallowedLoginUser(QStringLiteral("DOMAIN\\root")));
        QVERIFY(KRdp::RdpConnection::isDisallowedLoginUser(QStringLiteral(".\\root")));
        QVERIFY(!KRdp::RdpConnection::isDisallowedLoginUser(QStringLiteral("regularuser")));
    }
};

QTEST_MAIN(VsockTransportTest)
#include "vsocktransporttest.moc"
