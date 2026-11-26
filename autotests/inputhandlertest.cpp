// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QKeyEvent>
#include <QTest>

#include <memory>
#include <vector>

#include <freerdp/input.h>
#include <xkbcommon/xkbcommon.h>

#include "InputHandler.h"

class InputHandlerTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testScancodeMappingGermanKeysAltGrAndSync()
    {
        KRdp::InputHandler handler(nullptr);
        std::vector<std::shared_ptr<QKeyEvent>> received;
        connect(&handler, &KRdp::InputHandler::inputEvent, this, [&](const std::shared_ptr<QInputEvent> &ev) {
            if (ev->type() == QEvent::KeyPress || ev->type() == QEvent::KeyRelease) {
                received.push_back(std::static_pointer_cast<QKeyEvent>(ev));
            }
        });

        QVERIFY(handler.keyboardEvent(0x0C, KBD_FLAGS_DOWN)); // ß (AE11 -> evdev 12)
        QVERIFY(handler.keyboardEvent(0x0C, KBD_FLAGS_RELEASE));
        QVERIFY(handler.keyboardEvent(0x38, KBD_FLAGS_DOWN | KBD_FLAGS_EXTENDED)); // AltGr -> evdev 100
        QVERIFY(handler.keyboardEvent(0x0D, KBD_FLAGS_DOWN)); // dead acute -> evdev 13
        QVERIFY(handler.keyboardEvent(0x29, KBD_FLAGS_DOWN)); // dead circumflex -> evdev 41
        QVERIFY(handler.keyboardEvent(0x56, KBD_FLAGS_DOWN)); // <>| -> evdev 86
        QVERIFY(handler.keyboardEvent(0x56, KBD_FLAGS_RELEASE));
        QVERIFY(handler.keyboardEvent(0x54, KBD_FLAGS_DOWN)); // unmapped -> evdev 0 ignored

        QCOMPARE(received.size(), size_t(7));
        QCOMPARE(received[0]->nativeScanCode(), quint32(12));
        QCOMPARE(received[2]->nativeScanCode(), quint32(100));
        QCOMPARE(received[3]->nativeScanCode(), quint32(13));
        QCOMPARE(received[4]->nativeScanCode(), quint32(41));
        QCOMPARE(received[5]->nativeScanCode(), quint32(86));

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

        QVERIFY(handler.unicodeKeyboardEvent(0x00DF, KBD_FLAGS_DOWN)); // ß
        QVERIFY(handler.unicodeKeyboardEvent(0x00DF, KBD_FLAGS_RELEASE));
        QVERIFY(handler.unicodeKeyboardEvent(0x1E9E, KBD_FLAGS_DOWN)); // ẞ
        QVERIFY(handler.unicodeKeyboardEvent(0x20AC, KBD_FLAGS_DOWN)); // €
        QVERIFY(handler.unicodeKeyboardEvent(0xD83D, KBD_FLAGS_DOWN)); // high surrogate
        QCOMPARE(received.size(), size_t(4));
        QVERIFY(handler.unicodeKeyboardEvent(0xDE00, KBD_FLAGS_DOWN)); // low surrogate -> U+1F600
        QCOMPARE(received.size(), size_t(5));

        QCOMPARE(received[0]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x00DF)));
        QCOMPARE(received[1]->type(), QEvent::KeyRelease);
        QCOMPARE(received[2]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x1E9E)));
        QCOMPARE(received[3]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x20AC)));
        QCOMPARE(received[4]->nativeVirtualKey(), quint32(xkb_utf32_to_keysym(0x1F600)));
    }
};

QTEST_MAIN(InputHandlerTest)
#include "inputhandlertest.moc"
