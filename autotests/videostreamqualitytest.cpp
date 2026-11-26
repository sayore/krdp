// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QProcess>
#include <QTemporaryDir>
#include <QTest>

#include <array>
#include <filesystem>
#include <sys/socket.h>
#include <unistd.h>

#include "RdpConnection.h"
#include "Server.h"
#include "VideoStream.h"

class VideoStreamQualityTest : public QObject
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
                      {QStringLiteral("req"),
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
                       QStringLiteral("/CN=krdp-video-quality-test")});
        QVERIFY(openssl.waitForFinished(15000));
        QCOMPARE(openssl.exitCode(), 0);
    }

    void testRepeatedResizeAndStaticQualityLifecycle()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setUsePAMAuthentication(true);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);
        QVERIFY(server.start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        KRdp::RdpConnection conn(&server, fds[0]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);

        auto *vs = conn.videoStream();
        QVERIFY(vs != nullptr);

        // Configure VSOCK-style static high quality and exercise repeated resolution changes
        vs->setAdaptiveQuality(false);
        vs->setVideoQuality(95);
        vs->setRequestedSize(QSize(1920, 1080));
        vs->setRequestedSize(QSize(1280, 720));
        vs->setRequestedSize(QSize(2560, 1440));
        vs->setRequestedSize(QSize(1920, 1080));
        vs->setRequestedSize(QSize()); // empty size ignored cleanly
        vs->reset();

        // Toggle adaptive quality on (TCP behavior) and exercise seeding + resize
        vs->setAdaptiveQuality(true);
        vs->seedQuality(70);
        vs->setRequestedSize(QSize(1600, 900));

        // 100 repeated resize cycles across alternating resolutions (stress test)
        const std::array<QSize, 6> resolutions = {
            QSize(1920, 1080),
            QSize(1280, 720),
            QSize(2560, 1440),
            QSize(1366, 768),
            QSize(3840, 2160),
            QSize(1024, 768),
        };
        vs->setAdaptiveQuality(false);
        vs->setVideoQuality(95);
        for (int cycle = 0; cycle < 100; ++cycle) {
            const QSize &sz = resolutions[static_cast<size_t>(cycle) % resolutions.size()];
            vs->setRequestedSize(sz);
            if ((cycle % 5) == 0) {
                vs->reset();
            }
            KRdp::VideoFrame frame;
            frame.size = sz;
            frame.isKeyFrame = (cycle % 2) == 0;
            vs->queueFrame(frame);
        }

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
        server.stop();
    }
};

QTEST_MAIN(VideoStreamQualityTest)
#include "videostreamqualitytest.moc"
