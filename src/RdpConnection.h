// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <memory>
#include <thread>

#include <QObject>

#include <freerdp/freerdp.h>

#include "Server.h"
#include "krdp_export.h"

namespace KRdp
{

class InputHandler;
class InBandGreeter;
class Server;
class VideoStream;
class VideoStreamSurface;
class Cursor;
class NetworkDetection;
class Clipboard;
class DisplayControl;

/**
 * An RDP session.
 *
 * This represents an RDP session, that is, a connection between an RDP client
 * and the server. It primarily takes care of the RDP communication side of
 * things.
 *
 * Note that this class starts its own thread for performing the actual
 * communication.
 */
class KRDP_EXPORT RdpConnection : public QObject
{
    Q_OBJECT

public:
    /**
     * Session state.
     */
    enum class State {
        Initial,
        Starting,
        Running,
        Activated,
        Streaming,
        Closed,
    };

    /**
     * Reasons for closing the stream.
     */
    enum class CloseReason {
        None, ///< No particular reason, e.g. closing due to normal operation
              ///  like client disconnect.
        VideoInitFailed, ///< VideoStream failed to initialize.
    };

    /**
     * Authentication state of this RDP connection.
     *
     * Desktop screencasting, KWin EIS input, and Clipboard MUST NOT be attached
     * until authState() == AuthState::Authenticated.
     */
    enum class AuthState {
        Unauthenticated,
        PendingInBandGreeter,
        Authenticated,
    };

    /**
     * Transport metadata for an accepted connection.
     */
    struct TransportInfo {
        Server::Transport transport = Server::Transport::Tcp;
        bool vmConnectMode = false;
        bool inBandGreeterEnabled = false;
        quint32 vsockPeerCid = 0;
        quint32 vsockPeerPort = 0;
    };

    /**
     * Constructor.
     *
     * \param server The KRdp::Server instance this session is part of.
     * \param socketHandle A file handle to the socket this session should use
     *                     for communication.
     */
    explicit RdpConnection(Server *server, qintptr socketHandle);
    explicit RdpConnection(Server *server, qintptr socketHandle, const TransportInfo &transportInfo);
    ~RdpConnection() override;

    /**
     * Returns whether a username refers to root / UID 0 and must be rejected for RDP login.
     */
    static bool isDisallowedLoginUser(const QString &username);

    /**
     * The current session state.
     */
    State state() const;
    Q_SIGNAL void stateChanged(State newState);

    /**
     * The current authentication state.
     */
    AuthState authState() const;
    bool isAuthenticated() const;
    Q_SIGNAL void authStateChanged(AuthState newAuthState);
    Q_SIGNAL void authenticatedChanged(bool authenticated);

    /**
     * Validate guest username/password against PAM and/or configured non-root KRdp users.
     */
    bool verifyGuestCredentials(const QString &username, const QString &password) const;

    /**
     * The isolated in-band greeter used when a Hyper-V VMConnect peer connects without
     * a password in TS_INFO_PACKET.
     */
    InBandGreeter *inBandGreeter() const;

    /**
     * Close the connection
     *
     * \param reason The reason to close the connection. May set error state if
     *               it is something different than CloseReason::None.
     */
    void close(CloseReason reason = CloseReason::None);

    /**
     * The InputHandler instance associated with this session.
     */
    InputHandler *inputHandler() const;
    /**
     * The VideoStream instance associated with this session.
     */
    VideoStream *videoStream() const;
    /**
     * The Cursor instance associated with this session.
     */
    Cursor *cursor() const;

    Clipboard *clipboard() const;

    DisplayControl *displayControl() const;

    NetworkDetection *networkDetection() const;

private:
    friend BOOL peerCapabilities(freerdp_peer *);
    friend BOOL peerActivate(freerdp_peer *);
    friend BOOL peerPostConnect(freerdp_peer *);
    friend BOOL suppressOutput(rdpContext *, uint8_t, const RECTANGLE_16 *);

    friend class Cursor;
    friend class VideoStream;
    friend class VideoStreamSurface;
    friend class NetworkDetection;
    friend class Clipboard;
    friend class DisplayControl;

    void setState(State newState);
    void setAuthState(AuthState newAuthState);
    void startInBandGreeter();
    void initialize();
    void run(std::stop_token stopToken);

    freerdp_peer *rdpPeer() const;
    rdpContext *rdpPeerContext() const;

    bool onCapabilities();
    bool onActivate();
    bool onPostConnect();
    bool onClose();
    bool onSuppressOutput(uint8_t allow);

    class Private;
    const std::unique_ptr<Private> d;
};

}
