// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QKeyEvent>
#include <QProcess>
#include <QTemporaryDir>
#include <QTest>

#include <filesystem>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <freerdp/input.h>
#include <xkbcommon/xkbcommon.h>

#include "InBandGreeter.h"
#include "InputHandler.h"
#include "RdpConnection.h"
#include "Server.h"

class InputHandlerTest : public QObject
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
                       QStringLiteral("/CN=krdp-input-test")});
        QVERIFY(openssl.waitForFinished(15000));
        QCOMPARE(openssl.exitCode(), 0);
    }

    void testScancodeMappingGermanKeysAltGrAndSync()
    {
        KRdp::InputHandler handler(nullptr);
        std::vector<std::shared_ptr<QKeyEvent>> received;
        connect(&handler, &KRdp::InputHandler::inputEvent, this, [&](const std::shared_ptr<QInputEvent> &ev) {
            if (ev->type() == QEvent::KeyPress || ev->type() == QEvent::KeyRelease) {
                received.push_back(std::static_pointer_cast<QKeyEvent>(ev));
            }
        });

        // ß (DE AE11 = scancode 0x0C -> evdev 12)
        QVERIFY(handler.keyboardEvent(0x0C, KBD_FLAGS_DOWN));
        QVERIFY(handler.keyboardEvent(0x0C, KBD_FLAGS_RELEASE));
        // AltGr / Right Alt (scancode 0x38 | KBD_FLAGS_EXTENDED -> evdev 100)
        QVERIFY(handler.keyboardEvent(0x38, KBD_FLAGS_DOWN | KBD_FLAGS_EXTENDED));
        // Dead acute key (0x0D -> evdev 13) and dead circumflex (0x29 -> evdev 41)
        QVERIFY(handler.keyboardEvent(0x0D, KBD_FLAGS_DOWN));
        QVERIFY(handler.keyboardEvent(0x29, KBD_FLAGS_DOWN));
        // ISO <>| key (0x56 -> evdev 86)
        QVERIFY(handler.keyboardEvent(0x56, KBD_FLAGS_DOWN));
        QVERIFY(handler.keyboardEvent(0x56, KBD_FLAGS_RELEASE));
        // Unmapped scancode (0x54 -> evdev 0) must be ignored without emitting or sticking
        QVERIFY(handler.keyboardEvent(0x54, KBD_FLAGS_DOWN));

        QCOMPARE(received.size(), size_t(7));
        QCOMPARE(received[0]->nativeScanCode(), quint32(12));
        QCOMPARE(received[0]->type(), QEvent::KeyPress);
        QCOMPARE(received[1]->nativeScanCode(), quint32(12));
        QCOMPARE(received[1]->type(), QEvent::KeyRelease);
        QCOMPARE(received[2]->nativeScanCode(), quint32(100)); // AltGr
        QCOMPARE(received[3]->nativeScanCode(), quint32(13)); // Dead acute
        QCOMPARE(received[4]->nativeScanCode(), quint32(41)); // Dead circumflex
        QCOMPARE(received[5]->nativeScanCode(), quint32(86)); // <>|
        QCOMPARE(received[6]->nativeScanCode(), quint32(86));

        // SynchronizeEvent must release the 3 still-held keys (100, 13, 41) and never release keycode 0
        received.clear();
        QVERIFY(handler.synchronizeEvent(0));
        QCOMPARE(received.size(), size_t(3));
        for (const auto &ev : received) {
            QCOMPARE(ev->type(), QEvent::KeyRelease);
            QVERIFY(ev->nativeScanCode() != 0);
        }
    }

    void testUnicodeKeyboardEventsIncludingSsharpAndSurrogates()
    {
        KRdp::InputHandler handler(nullptr);
        std::vector<std::shared_ptr<QKeyEvent>> received;
        connect(&handler, &KRdp::InputHandler::inputEvent, this, [&](const std::shared_ptr<QInputEvent> &ev) {
            if (ev->type() == QEvent::KeyPress || ev->type() == QEvent::KeyRelease) {
                received.push_back(std::static_pointer_cast<QKeyEvent>(ev));
            }
        });

        // ß (U+00DF), ẞ (U+1E9E), € (U+20AC)
        QVERIFY(handler.unicodeKeyboardEvent(0x00DF, KBD_FLAGS_DOWN));
        QVERIFY(handler.unicodeKeyboardEvent(0x00DF, KBD_FLAGS_RELEASE));
        QVERIFY(handler.unicodeKeyboardEvent(0x1E9E, KBD_FLAGS_DOWN));
        QVERIFY(handler.unicodeKeyboardEvent(0x20AC, KBD_FLAGS_DOWN));

        // UTF-16 surrogate pair for U+1F600 (0xD83D, 0xDE00)
        QVERIFY(handler.unicodeKeyboardEvent(0xD83D, KBD_FLAGS_DOWN));
        QCOMPARE(received.size(), size_t(4)); // high surrogate buffered until low surrogate arrives
        QVERIFY(handler.unicodeKeyboardEvent(0xDE00, KBD_FLAGS_DOWN));
        QCOMPARE(received.size(), size_t(5));

        QCOMPARE(received[0]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x00DF)));
        QCOMPARE(received[1]->type(), QEvent::KeyRelease);
        QCOMPARE(received[2]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x1E9E)));
        QCOMPARE(received[3]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x20AC)));
        QCOMPARE(received[4]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x1F600)));
    }

    void testGreeterGermanSsharpAltGrAndDeadKeyCompose()
    {
        // Password combines ß, AltGr chars (\ @ € |), and dead-key composed chars (é = ´ + e, â = ^ + a)
        const QString expectedPass = QString::fromUtf8("ß\\@€|éâ");

        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setUsePAMAuthentication(false);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);
        server.addUser(KRdp::User{QStringLiteral("deuser"), expectedPass, false});
        QVERIFY(server.start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        KRdp::RdpConnection conn(&server, fds[0]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);

        auto *greeter = conn.inBandGreeter();
        QVERIFY(greeter != nullptr);
        greeter->setKeyboardLayout(0x00000407u); // German (Germany)
        greeter->start(QSize(1280, 720), QStringLiteral("deuser"));
        QVERIFY(greeter->isActive());

        auto tap = [&](quint32 evdev) {
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyPress, 0, Qt::NoModifier, evdev, 0, 0));
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyRelease, 0, Qt::NoModifier, evdev, 0, 0));
        };
        auto tapWithAltGr = [&](quint32 evdev) {
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyPress, 0, Qt::NoModifier, 100 /* RALT / AltGr */, 0, 0));
            tap(evdev);
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyRelease, 0, Qt::NoModifier, 100 /* RALT / AltGr */, 0, 0));
        };

        tap(12); // ß
        tapWithAltGr(12); // backslash
        tapWithAltGr(16); // @ (AltGr + Q)
        tapWithAltGr(18); // € (AltGr + E)
        tapWithAltGr(86); // | (AltGr + <)
        tap(13); // dead_acute (´)
        tap(18); // e -> é
        tap(41); // dead_circumflex (^)
        tap(30); // a -> â
        tap(28); // Return -> submit

        QTRY_VERIFY_WITH_TIMEOUT(conn.isAuthenticated(), 2000);

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
        server.stop();
    }
};

QTEST_MAIN(InputHandlerTest)
#include "inputhandlertest.moc"
