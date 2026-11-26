// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <memory>

#include <QImage>
#include <QInputEvent>
#include <QObject>
#include <QSize>
#include <QString>

#include "krdp_export.h"

namespace KRdp
{

class RdpConnection;

/**
 * Isolated in-band login greeter rendered directly over RDPGFX Progressive frames
 * for Hyper-V VMConnect (AF_VSOCK) connections that do not supply guest credentials
 * in TS_INFO_PACKET (e.g. vmconnect.exe).
 *
 * No PipeWire screencast, KWin session, EIS input, or Clipboard is ever attached
 * until this greeter validates non-root guest credentials via PAM / configured users.
 */
class KRDP_EXPORT InBandGreeter : public QObject
{
    Q_OBJECT

public:
    static constexpr int MaxFailedAttempts = 5;
    static constexpr int FailureCooldownMs = 1000;
    static constexpr int IdleTimeoutMs = 120000;

    explicit InBandGreeter(RdpConnection *connection, QObject *parent = nullptr);
    ~InBandGreeter() override;

    void start(const QSize &initialSize, const QString &defaultUsername = QString());
    void stop();

    bool isActive() const;
    int failedAttempts() const;

    void setScreenSize(const QSize &size);
    void handleInputEvent(const std::shared_ptr<QInputEvent> &event);

    /**
     * Validate and submit credentials. Clears any internal password buffer afterwards.
     * Returns true if authentication succeeded.
     */
    bool submitCredentials(const QString &username, const QString &password);

    /**
     * Render the current greeter frame (useful for VideoStream submission and tests).
     */
    QImage renderFrame() const;

    Q_SIGNAL void frameReady(const QImage &frame);
    Q_SIGNAL void authenticated(const QString &username);
    Q_SIGNAL void failedAndClose(const QString &reason);

private:
    enum class FocusField {
        Username,
        Password,
    };

    void submitCurrentInputs();
    void clearPasswordBuffer();
    void emitFrame();
    void resetIdleTimer();

    class Private;
    const std::unique_ptr<Private> d;
};

}
