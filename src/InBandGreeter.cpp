// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "InBandGreeter.h"

#include <cstring>

#include <QColor>
#include <QElapsedTimer>
#include <QFont>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QRect>
#include <QTimer>

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

    xkb_context *xkbCtx = nullptr;
    xkb_keymap *xkbKeymap = nullptr;
    xkb_state *xkbState = nullptr;

    void initXkb()
    {
        if (xkbCtx) {
            return;
        }
        xkbCtx = xkb_context_new(XKB_CONTEXT_NO_FLAGS);
        if (!xkbCtx) {
            return;
        }
        xkb_rule_names names{};
        xkbKeymap = xkb_keymap_new_from_names(xkbCtx, &names, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (xkbKeymap) {
            xkbState = xkb_state_new(xkbKeymap);
        }
    }

    void cleanupXkb()
    {
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

    // Periodic gentle redraw while greeter is visible so clients that open RDPGFX
    // slightly after start always receive the login screen promptly.
    d->refreshTimer.setSingleShot(false);
    d->refreshTimer.setInterval(1000);
    connect(&d->refreshTimer, &QTimer::timeout, this, [this]() {
        if (d->active) {
            emitFrame();
        }
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

    resetIdleTimer();
    d->refreshTimer.start();
    emitFrame();
}

void InBandGreeter::stop()
{
    d->active = false;
    d->idleTimer.stop();
    d->refreshTimer.stop();
    clearPasswordBuffer();
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
    d->screenSize = size;
    if (d->active) {
        emitFrame();
    }
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

    if (event->type() == QEvent::MouseButtonPress) {
        const auto *mouse = static_cast<const QMouseEvent *>(event.get());
        if (mouse->button() == Qt::LeftButton) {
            const QPoint pt = mouse->position().toPoint();
            const CardLayout layout = computeLayout(d->screenSize);
            if (layout.userFieldRect.contains(pt)) {
                d->focus = FocusField::Username;
                emitFrame();
            } else if (layout.passFieldRect.contains(pt)) {
                d->focus = FocusField::Password;
                emitFrame();
            } else if (layout.buttonRect.contains(pt)) {
                submitCurrentInputs();
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
            char utf8Buf[32] = {};
            const int len = xkb_state_key_get_utf8(d->xkbState, xkbCode, utf8Buf, sizeof(utf8Buf));
            if (len > 0) {
                text = QString::fromUtf8(utf8Buf, len);
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
            emitFrame();
        } else {
            submitCurrentInputs();
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
        const QString shown = focused ? (displayText + QStringLiteral("|")) : displayText;
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
    Q_EMIT frameReady(renderFrame());
}

}

#include "moc_InBandGreeter.cpp"
