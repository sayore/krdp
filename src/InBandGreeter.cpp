// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "InBandGreeter.h"

#include <cstdlib>
#include <cstring>

#include <QColor>
#include <QElapsedTimer>
#include <QFile>
#include <QFont>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QRect>
#include <QTimer>

#include <xkbcommon/xkbcommon-compose.h>
#include <xkbcommon/xkbcommon.h>

#include "RdpConnection.h"
#include "krdp_logging.h"

namespace KRdp
{

namespace
{
void wipeQString(QString &str)
{
    if (!str.isEmpty()) {
        explicit_bzero(str.data(), static_cast<size_t>(str.size()) * sizeof(QChar));
        str.clear();
    }
}

struct CardLayout {
    QRect cardRect;
    QRect userFieldRect;
    QRect passFieldRect;
    QRect buttonRect;
};

CardLayout computeLayout(const QSize &size)
{
    const int w = std::max(640, size.width());
    const int h = std::max(480, size.height());
    const int cardW = std::min(460, w - 60);
    const int cardH = 340;
    const int cx = (w - cardW) / 2;
    const int cy = (h - cardH) / 2;

    CardLayout l;
    l.cardRect = QRect(cx, cy, cardW, cardH);
    l.userFieldRect = QRect(cx + 36, cy + 122, cardW - 72, 40);
    l.passFieldRect = QRect(cx + 36, cy + 194, cardW - 72, 40);
    l.buttonRect = QRect(cx + 36, cy + 256, cardW - 72, 42);
    return l;
}
}

class KRDP_NO_EXPORT InBandGreeter::Private
{
public:
    RdpConnection *connection = nullptr;
    bool active = false;
    QSize screenSize{1280, 720};
    FocusField focus = FocusField::Password;

    QString username;
    QString password;
    QString statusMessage;
    bool statusIsError = false;

    int failedAttempts = 0;
    QElapsedTimer lastFailureTimer;
    bool hasRecentFailure = false;

    QTimer idleTimer;
    QTimer refreshTimer;
    QTimer blinkTimer;
    bool caretVisible = true;
    uint64_t framesEmitted = 0;

    quint32 rdpKeyboardLayout = 0;
    QByteArray xkbLayoutName;
    QByteArray xkbVariantName;
    xkb_context *xkbCtx = nullptr;
    xkb_keymap *xkbKeymap = nullptr;
    xkb_state *xkbState = nullptr;
    xkb_compose_table *xkbComposeTable = nullptr;
    xkb_compose_state *xkbComposeState = nullptr;

    void resolveXkbNames()
    {
        xkbLayoutName.clear();
        xkbVariantName.clear();

        // Map Windows RDP KeyboardLayout LCID (CS_CORE keyboardLayout) to XKB layout.
        const quint16 langId = static_cast<quint16>(rdpKeyboardLayout & 0xFFFFu);
        switch (langId) {
        case 0x0407: // German (Germany)
        case 0x0C07: // German (Austria)
            xkbLayoutName = "de";
            break;
        case 0x0807: // German (Switzerland)
            xkbLayoutName = "ch";
            break;
        case 0x0409: // English (US)
            xkbLayoutName = "us";
            break;
        case 0x0809: // English (UK)
            xkbLayoutName = "gb";
            break;
        case 0x040C: // French (France)
            xkbLayoutName = "fr";
            break;
        case 0x0410: // Italian
            xkbLayoutName = "it";
            break;
        case 0x040A: // Spanish
            xkbLayoutName = "es";
            break;
        case 0x0413: // Dutch
            xkbLayoutName = "nl";
            break;
        case 0x0415: // Polish
            xkbLayoutName = "pl";
            break;
        case 0x041D: // Swedish
            xkbLayoutName = "se";
            break;
        case 0x0414: // Norwegian
            xkbLayoutName = "no";
            break;
        case 0x0406: // Danish
            xkbLayoutName = "dk";
            break;
        case 0x040B: // Finnish
            xkbLayoutName = "fi";
            break;
        case 0x0816: // Portuguese (Portugal)
            xkbLayoutName = "pt";
            break;
        case 0x0416: // Portuguese (Brazil)
            xkbLayoutName = "br";
            break;
        default:
            break;
        }

        // Fall back to /etc/vconsole.conf XKBLAYOUT / XKBVARIANT if RDP did not specify a mapped layout.
        if (xkbLayoutName.isEmpty()) {
            QFile vc(QStringLiteral("/etc/vconsole.conf"));
            if (vc.open(QIODevice::ReadOnly | QIODevice::Text)) {
                const QList<QByteArray> lines = vc.readAll().split('\n');
                for (const QByteArray &raw : lines) {
                    const QByteArray line = raw.trimmed();
                    if (line.startsWith("XKBLAYOUT=")) {
                        xkbLayoutName = line.mid(10).trimmed().replace('"', "");
                    } else if (line.startsWith("XKBVARIANT=")) {
                        xkbVariantName = line.mid(11).trimmed().replace('"', "");
                    }
                }
            }
        }
    }

    void initXkb()
    {
        cleanupXkb();
        resolveXkbNames();
        xkbCtx = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
        if (!xkbCtx) {
            return;
        }
        xkb_rule_names names{};
        if (!xkbLayoutName.isEmpty()) {
            names.layout = xkbLayoutName.constData();
        }
        if (!xkbVariantName.isEmpty()) {
            names.variant = xkbVariantName.constData();
        }
        xkbKeymap = xkb_keymap_new_from_names(xkbCtx, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (!xkbKeymap && !xkbLayoutName.isEmpty()) {
            xkbLayoutName.clear();
            xkbVariantName.clear();
            xkb_rule_names fallback{};
            xkbKeymap = xkb_keymap_new_from_names(xkbCtx, &fallback, XKB_KEYMAP_COMPILE_NO_FLAGS);
        }
        if (xkbKeymap) {
            xkbState = xkb_state_new(xkbKeymap);
        }

        // Load XKB compose table for dead keys and composed characters (e.g. ´ + e -> é, ^ + a -> â).
        const char *locales[] = {
            std::getenv("LC_ALL"),
            std::getenv("LC_CTYPE"),
            std::getenv("LANG"),
            "en_US.UTF-8",
            "C.UTF-8",
            "C",
        };
        for (const char *loc : locales) {
            if (!loc || loc[0] == '\0') {
                continue;
            }
            xkbComposeTable = xkb_compose_table_new_from_locale(xkbCtx, loc, XKB_COMPOSE_COMPILE_NO_FLAGS);
            if (xkbComposeTable) {
                xkbComposeState = xkb_compose_state_new(xkbComposeTable, XKB_COMPOSE_STATE_NO_FLAGS);
                break;
            }
        }
    }

    void cleanupXkb()
    {
        if (xkbComposeState) {
            xkb_compose_state_unref(xkbComposeState);
            xkbComposeState = nullptr;
        }
        if (xkbComposeTable) {
            xkb_compose_table_unref(xkbComposeTable);
            xkbComposeTable = nullptr;
        }
        if (xkbState) {
            xkb_state_unref(xkbState);
            xkbState = nullptr;
        }
        if (xkbKeymap) {
            xkb_keymap_unref(xkbKeymap);
            xkbKeymap = nullptr;
        }
        if (xkbCtx) {
            xkb_context_unref(xkbCtx);
            xkbCtx = nullptr;
        }
    }
};

InBandGreeter::InBandGreeter(RdpConnection *connection, QObject *parent)
    : QObject(parent)
    , d(std::make_unique<Private>())
{
    d->connection = connection;

    d->idleTimer.setSingleShot(true);
    d->idleTimer.setInterval(IdleTimeoutMs);
    connect(&d->idleTimer, &QTimer::timeout, this, [this]() {
        if (!d->active) {
            return;
        }
        qCWarning(KRDP) << "In-band greeter timed out waiting for guest authentication";
        stop();
        Q_EMIT failedAndClose(QStringLiteral("Authentication timeout"));
    });

    // Single-shot startup fallback redraw in case RDPGFX finishes confirming slightly
    // after start(). Subsequent redraws are driven by VideoStream::capsConfirmed(),
    // resize events, and interactive input so idle greeter sessions never flood the
    // RDPGFX in-flight acknowledgement window with redundant full-screen frames.
    d->refreshTimer.setSingleShot(true);
    d->refreshTimer.setInterval(1500);
    connect(&d->refreshTimer, &QTimer::timeout, this, [this]() {
        if (d->active) {
            qCInfo(KRDP) << "In-band greeter emitting startup fallback frame";
            emitFrame();
        }
    });

    d->blinkTimer.setSingleShot(false);
    d->blinkTimer.setInterval(550);
    connect(&d->blinkTimer, &QTimer::timeout, this, [this]() {
        if (!d->active) {
            return;
        }
        d->caretVisible = !d->caretVisible;
        emitFrame();
    });
}

InBandGreeter::~InBandGreeter()
{
    clearPasswordBuffer();
    d->cleanupXkb();
}

void InBandGreeter::start(const QSize &initialSize, const QString &defaultUsername)
{
    if (d->active) {
        return;
    }

    d->initXkb();
    d->active = true;
    d->failedAttempts = 0;
    d->hasRecentFailure = false;
    d->statusIsError = false;
    d->statusMessage = QStringLiteral("Enter your Linux guest credentials to unlock the Plasma session.");

    if (initialSize.width() >= 640 && initialSize.height() >= 480) {
        d->screenSize = initialSize;
    } else {
        d->screenSize = QSize(1280, 720);
    }

    if (!defaultUsername.isEmpty() && !RdpConnection::isDisallowedLoginUser(defaultUsername)) {
        d->username = defaultUsername;
        d->focus = FocusField::Password;
    } else {
        d->username.clear();
        d->focus = FocusField::Username;
    }
    clearPasswordBuffer();

    d->framesEmitted = 0;
    d->caretVisible = true;
    resetIdleTimer();
    d->refreshTimer.start();
    d->blinkTimer.start();
    qCInfo(KRDP) << "In-band greeter started: size" << d->screenSize << "xkbReady" << (d->xkbState != nullptr) << "xkbLayout"
                 << (d->xkbLayoutName.isEmpty() ? QByteArray("default") : d->xkbLayoutName) << "rdpKbdLayout" << Qt::hex << d->rdpKeyboardLayout << Qt::dec
                 << "defaultUserPrefilled" << !d->username.isEmpty() << "initialFocus" << (d->focus == FocusField::Username ? "Username" : "Password");
    emitFrame();
}

void InBandGreeter::stop()
{
    const bool wasActive = d->active;
    d->active = false;
    d->idleTimer.stop();
    d->refreshTimer.stop();
    d->blinkTimer.stop();
    clearPasswordBuffer();
    if (wasActive) {
        qCInfo(KRDP) << "In-band greeter stopped after" << d->framesEmitted << "emitted frame(s)";
    }
}

bool InBandGreeter::isActive() const
{
    return d->active;
}

int InBandGreeter::failedAttempts() const
{
    return d->failedAttempts;
}

void InBandGreeter::setScreenSize(const QSize &size)
{
    if (size.width() < 640 || size.height() < 480 || size == d->screenSize) {
        return;
    }
    qCInfo(KRDP) << "In-band greeter screen size changed:" << d->screenSize << "->" << size;
    d->screenSize = size;
    if (d->active) {
        emitFrame();
    }
}

void InBandGreeter::setKeyboardLayout(quint32 rdpKeyboardLayout)
{
    d->rdpKeyboardLayout = rdpKeyboardLayout;
    if (d->active) {
        d->initXkb();
    }
}

void InBandGreeter::requestRedraw()
{
    if (!d->active) {
        return;
    }
    d->refreshTimer.stop();
    qCInfo(KRDP) << "In-band greeter redraw requested (e.g. RDPGFX caps confirmed)";
    emitFrame();
}

void InBandGreeter::clearPasswordBuffer()
{
    wipeQString(d->password);
}

void InBandGreeter::resetIdleTimer()
{
    if (d->active) {
        d->idleTimer.start();
    }
}

void InBandGreeter::handleInputEvent(const std::shared_ptr<QInputEvent> &event)
{
    if (!d->active || !event) {
        return;
    }

    resetIdleTimer();
    if (event->type() == QEvent::KeyPress || event->type() == QEvent::MouseButtonPress) {
        d->caretVisible = true;
        d->blinkTimer.start();
    }

    if (event->type() == QEvent::MouseButtonPress) {
        const auto *mouse = static_cast<const QMouseEvent *>(event.get());
        if (mouse->button() == Qt::LeftButton) {
            const QPoint pt = mouse->position().toPoint();
            const CardLayout layout = computeLayout(d->screenSize);
            if (layout.userFieldRect.contains(pt)) {
                if (d->focus != FocusField::Username) {
                    qCInfo(KRDP) << "In-band greeter focus changed -> Username (mouse)";
                }
                d->focus = FocusField::Username;
                emitFrame();
            } else if (layout.passFieldRect.contains(pt)) {
                if (d->focus != FocusField::Password) {
                    qCInfo(KRDP) << "In-band greeter focus changed -> Password (mouse)";
                }
                d->focus = FocusField::Password;
                emitFrame();
            } else if (layout.buttonRect.contains(pt)) {
                qCInfo(KRDP) << "In-band greeter Sign In triggered (mouse)";
                QMetaObject::invokeMethod(this, &InBandGreeter::submitCurrentInputs, Qt::QueuedConnection);
            }
        }
        return;
    }

    if (event->type() != QEvent::KeyPress && event->type() != QEvent::KeyRelease) {
        return;
    }

    const auto *key = static_cast<const QKeyEvent *>(event.get());
    const bool isPress = (event->type() == QEvent::KeyPress);
    xkb_keysym_t sym = XKB_KEY_NoSymbol;
    QString text;

    if (key->nativeScanCode() != 0 && d->xkbState) {
        // FreeRDP InputHandler sends Linux evdev keycodes; XKB keycodes are evdev + 8.
        const xkb_keycode_t xkbCode = static_cast<xkb_keycode_t>(key->nativeScanCode() + 8);
        sym = xkb_state_key_get_one_sym(d->xkbState, xkbCode);
        if (isPress) {
            bool handledByCompose = false;
            if (d->xkbComposeState && sym != XKB_KEY_NoSymbol) {
                if (xkb_compose_state_feed(d->xkbComposeState, sym) == XKB_COMPOSE_FEED_ACCEPTED) {
                    const xkb_compose_status status = xkb_compose_state_get_status(d->xkbComposeState);
                    if (status == XKB_COMPOSE_COMPOSING) {
                        handledByCompose = true;
                        sym = XKB_KEY_NoSymbol;
                    } else if (status == XKB_COMPOSE_COMPOSED) {
                        char composeBuf[64] = {};
                        const int clen = xkb_compose_state_get_utf8(d->xkbComposeState, composeBuf, sizeof(composeBuf));
                        if (clen > 0) {
                            text = QString::fromUtf8(composeBuf, clen);
                        }
                        const xkb_keysym_t composedSym = xkb_compose_state_get_one_sym(d->xkbComposeState);
                        if (composedSym != XKB_KEY_NoSymbol) {
                            sym = composedSym;
                        }
                        xkb_compose_state_reset(d->xkbComposeState);
                        handledByCompose = true;
                    } else if (status == XKB_COMPOSE_CANCELLED) {
                        xkb_compose_state_reset(d->xkbComposeState);
                        handledByCompose = true;
                        sym = XKB_KEY_NoSymbol;
                    }
                }
            }
            if (!handledByCompose) {
                char utf8Buf[32] = {};
                const int len = xkb_state_key_get_utf8(d->xkbState, xkbCode, utf8Buf, sizeof(utf8Buf));
                if (len > 0) {
                    text = QString::fromUtf8(utf8Buf, len);
                }
            }
        }
        xkb_state_update_key(d->xkbState, xkbCode, isPress ? XKB_KEY_DOWN : XKB_KEY_UP);
    } else if (key->nativeVirtualKey() != 0) {
        sym = static_cast<xkb_keysym_t>(key->nativeVirtualKey());
        if (isPress) {
            const uint32_t cp = xkb_keysym_to_utf32(sym);
            if (cp >= 0x20 && cp != 0x7F) {
                text = QString::fromUcs4(reinterpret_cast<const char32_t *>(&cp), 1);
            }
        }
    }

    if (!isPress) {
        return;
    }

    if (sym == XKB_KEY_Tab || sym == XKB_KEY_ISO_Left_Tab) {
        d->focus = (d->focus == FocusField::Username) ? FocusField::Password : FocusField::Username;
        qCInfo(KRDP) << "In-band greeter focus changed ->" << (d->focus == FocusField::Username ? "Username" : "Password") << "(Tab)";
        emitFrame();
        return;
    }

    if (sym == XKB_KEY_Escape) {
        clearPasswordBuffer();
        d->statusIsError = false;
        d->statusMessage = QStringLiteral("Password field cleared.");
        emitFrame();
        return;
    }

    if (sym == XKB_KEY_Return || sym == XKB_KEY_KP_Enter) {
        if (d->focus == FocusField::Username && d->password.isEmpty()) {
            d->focus = FocusField::Password;
            qCInfo(KRDP) << "In-band greeter focus changed -> Password (Return)";
            emitFrame();
        } else {
            qCInfo(KRDP) << "In-band greeter Sign In triggered (Return)";
            QMetaObject::invokeMethod(this, &InBandGreeter::submitCurrentInputs, Qt::QueuedConnection);
        }
        return;
    }

    if (sym == XKB_KEY_BackSpace) {
        if (d->focus == FocusField::Username) {
            if (!d->username.isEmpty()) {
                d->username.chop(1);
            }
        } else {
            if (!d->password.isEmpty()) {
                d->password.back() = QChar(u'\0');
                d->password.chop(1);
            }
        }
        emitFrame();
        return;
    }

    // Printable character entry
    if (!text.isEmpty() && !text.at(0).isNull() && text.at(0).unicode() >= 0x20 && text.at(0).unicode() != 0x7F) {
        if (d->focus == FocusField::Username) {
            if (d->username.size() < 64) {
                d->username.append(text);
                emitFrame();
            }
        } else {
            if (d->password.size() < 128) {
                d->password.append(text);
                emitFrame();
            }
        }
    }
}

void InBandGreeter::submitCurrentInputs()
{
    QString userCopy = d->username.trimmed();
    QString passCopy = d->password;
    clearPasswordBuffer();

    const bool ok = submitCredentials(userCopy, passCopy);
    wipeQString(passCopy);
    Q_UNUSED(ok);
}

bool InBandGreeter::submitCredentials(const QString &username, const QString &password)
{
    if (!d->active || !d->connection) {
        return false;
    }

    if (d->hasRecentFailure && d->lastFailureTimer.elapsed() < FailureCooldownMs) {
        d->statusIsError = true;
        d->statusMessage = QStringLiteral("Please wait a moment before trying again.");
        emitFrame();
        return false;
    }

    const QString normalized = username.section(QLatin1Char('\\'), -1).trimmed();
    if (normalized.isEmpty() || password.isEmpty()) {
        d->statusIsError = true;
        d->statusMessage = QStringLiteral("Username and password are required.");
        emitFrame();
        return false;
    }

    if (RdpConnection::isDisallowedLoginUser(normalized)) {
        d->failedAttempts++;
        d->hasRecentFailure = true;
        d->lastFailureTimer.start();
        qCWarning(KRDP) << "In-band greeter rejected disallowed login user:" << normalized;
        if (d->failedAttempts >= MaxFailedAttempts) {
            stop();
            Q_EMIT failedAndClose(QStringLiteral("Maximum failed login attempts exceeded"));
            return false;
        }
        d->statusIsError = true;
        d->statusMessage = QStringLiteral("Root login is not permitted (%1/%2 attempts).").arg(d->failedAttempts).arg(MaxFailedAttempts);
        emitFrame();
        return false;
    }

    if (d->connection->verifyGuestCredentials(normalized, password)) {
        qCInfo(KRDP) << "In-band greeter authenticated guest user:" << normalized;
        stop();
        Q_EMIT authenticated(normalized);
        return true;
    }

    d->failedAttempts++;
    d->hasRecentFailure = true;
    d->lastFailureTimer.start();
    qCWarning(KRDP) << "In-band greeter authentication failed for user" << normalized << "(" << d->failedAttempts << "/" << MaxFailedAttempts << ")";

    if (d->failedAttempts >= MaxFailedAttempts) {
        stop();
        Q_EMIT failedAndClose(QStringLiteral("Maximum failed login attempts exceeded"));
        return false;
    }

    d->statusIsError = true;
    d->statusMessage = QStringLiteral("Authentication failed (%1/%2 attempts).").arg(d->failedAttempts).arg(MaxFailedAttempts);
    d->focus = FocusField::Password;
    emitFrame();
    return false;
}

QImage InBandGreeter::renderFrame() const
{
    const QSize sz(std::max(640, d->screenSize.width()), std::max(480, d->screenSize.height()));
    QImage img(sz, QImage::Format_RGB32);
    img.fill(QColor(0x14, 0x18, 0x20));

    QPainter p(&img);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::TextAntialiasing, true);

    const CardLayout layout = computeLayout(sz);

    // Card background
    QPainterPath cardPath;
    cardPath.addRoundedRect(layout.cardRect, 12, 12);
    p.fillPath(cardPath, QColor(0x1e, 0x24, 0x30));
    p.setPen(QPen(QColor(0x3b, 0x45, 0x59), 1.5));
    p.drawPath(cardPath);

    // Header
    QFont titleFont(QStringLiteral("Sans Serif"), 16, QFont::Bold);
    p.setFont(titleFont);
    p.setPen(QColor(0xec, 0xf0, 0xf5));
    p.drawText(QRect(layout.cardRect.left() + 36, layout.cardRect.top() + 24, layout.cardRect.width() - 72, 30),
               Qt::AlignLeft | Qt::AlignVCenter,
               QStringLiteral("FOXCORE — KDE Plasma Wayland"));

    QFont subFont(QStringLiteral("Sans Serif"), 10);
    p.setFont(subFont);
    p.setPen(QColor(0x9a, 0xa8, 0xbc));
    p.drawText(QRect(layout.cardRect.left() + 36, layout.cardRect.top() + 54, layout.cardRect.width() - 72, 22),
               Qt::AlignLeft | Qt::AlignVCenter,
               QStringLiteral("Hyper-V Enhanced Session Login (AF_VSOCK)"));

    // Labels
    QFont labelFont(QStringLiteral("Sans Serif"), 10, QFont::DemiBold);
    p.setFont(labelFont);
    p.setPen(QColor(0xc9, 0xd4, 0xe4));
    p.drawText(QRect(layout.userFieldRect.left(), layout.userFieldRect.top() - 22, layout.userFieldRect.width(), 20),
               Qt::AlignLeft | Qt::AlignVCenter,
               QStringLiteral("Username"));
    p.drawText(QRect(layout.passFieldRect.left(), layout.passFieldRect.top() - 22, layout.passFieldRect.width(), 20),
               Qt::AlignLeft | Qt::AlignVCenter,
               QStringLiteral("Password"));

    auto drawInputBox = [&](const QRect &rect, const QString &displayText, bool focused) {
        QPainterPath boxPath;
        boxPath.addRoundedRect(rect, 6, 6);
        p.fillPath(boxPath, QColor(0x12, 0x16, 0x1e));
        p.setPen(QPen(focused ? QColor(0x3d, 0xae, 0xe9) : QColor(0x45, 0x50, 0x65), focused ? 2.0 : 1.0));
        p.drawPath(boxPath);

        QFont inputFont(QStringLiteral("Sans Serif"), 11);
        p.setFont(inputFont);
        p.setPen(QColor(0xf2, 0xf5, 0xfa));
        const QString shown = (focused && d->caretVisible) ? (displayText + QStringLiteral("|")) : displayText;
        p.drawText(rect.adjusted(12, 0, -12, 0), Qt::AlignLeft | Qt::AlignVCenter, shown);
    };

    drawInputBox(layout.userFieldRect, d->username, d->focus == FocusField::Username);
    drawInputBox(layout.passFieldRect, QString(d->password.size(), QChar(0x2022)), d->focus == FocusField::Password);

    // Sign In button
    QPainterPath btnPath;
    btnPath.addRoundedRect(layout.buttonRect, 6, 6);
    p.fillPath(btnPath, QColor(0x1d, 0x76, 0xb8));
    p.setPen(QColor(0xff, 0xff, 0xff));
    p.setFont(QFont(QStringLiteral("Sans Serif"), 11, QFont::Bold));
    p.drawText(layout.buttonRect, Qt::AlignCenter, QStringLiteral("Sign In (Enter)"));

    // Status message
    QFont statusFont(QStringLiteral("Sans Serif"), 9);
    p.setFont(statusFont);
    p.setPen(d->statusIsError ? QColor(0xff, 0x7a, 0x7a) : QColor(0x9a, 0xa8, 0xbc));
    p.drawText(QRect(layout.cardRect.left() + 36, layout.buttonRect.bottom() + 8, layout.cardRect.width() - 72, 32),
               Qt::AlignLeft | Qt::AlignVCenter | Qt::TextWordWrap,
               d->statusMessage);

    return img;
}

void InBandGreeter::emitFrame()
{
    if (!d->active) {
        return;
    }
    d->framesEmitted++;
    if (d->framesEmitted <= 3) {
        qCInfo(KRDP) << "In-band greeter emitting frame" << d->framesEmitted << "size" << d->screenSize;
    }
    Q_EMIT frameReady(renderFrame());
}

}

#include "moc_InBandGreeter.cpp"
