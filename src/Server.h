// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <filesystem>
#include <memory>

#include <QTcpServer>

#include <freerdp/settings.h>

#include "krdp_export.h"

namespace KRdp
{

class RdpConnection;

/**
 * Data required per user that is allowed to connect to the server.
 */
struct User {
    QString name; ///< The user name used to connect.
    QString password; ///< The password for the user.
    bool readOnly = false; ///< Whether this user is allowed to control the session.
};

/**
 * Core RDP server class.
 *
 * This class listens for TCP connections and creates a new @c Session for each
 * incoming connection. It takes care of basic system initialisation. It also
 * stores connection and security settings.
 */
class KRDP_EXPORT Server : public QTcpServer
{
    Q_OBJECT

public:
    enum class Transport {
        Tcp,
        Vsock,
    };
    Q_ENUM(Transport)

    explicit Server(QObject *parent = nullptr);
    ~Server() override;

    /**
     * Start listening for incoming connections.
     *
     * Note that `transport`, `address`, and `port` should be set before calling this,
     * changing them after the server has started listening has no effect.
     */
    bool start();
    /**
     * Stop listening for incoming connections.
     */
    void stop();

    /**
     * The transport used to accept incoming RDP connections.
     *
     * Defaults to Transport::Tcp.
     */
    Transport transport() const;
    void setTransport(Transport newTransport);

    /**
     * Whether Hyper-V VMConnect mode (FreeRDP_VmConnectMode) is enabled.
     *
     * This capability is strictly restricted to Transport::Vsock connections
     * from the authorized Hyper-V host peer CID. Enabling it on Transport::Tcp
     * causes start() to fail.
     */
    bool hyperVMode() const;
    void setHyperVMode(bool enabled);

    /**
     * Whether the isolated in-band login greeter is enabled for Hyper-V VMConnect
     * connections that do not send a password in TS_INFO_PACKET (e.g. vmconnect.exe).
     *
     * Strictly restricted to Transport::Vsock with hyperVMode() == true.
     * Enabling it on Transport::Tcp causes start() to fail.
     */
    bool inBandGreeterEnabled() const;
    void setInBandGreeterEnabled(bool enabled);

    /**
     * The AF_VSOCK CID to bind to when transport() == Transport::Vsock.
     *
     * Defaults to VMADDR_CID_ANY (0xFFFFFFFFU).
     */
    quint32 vsockBindCid() const;
    void setVsockBindCid(quint32 cid);

    /**
     * The only AF_VSOCK peer CID permitted to connect when transport() == Transport::Vsock.
     *
     * Defaults to VMADDR_CID_HOST (2), enforcing the Hyper-V host trust boundary.
     * Wildcard VMADDR_CID_ANY (0xFFFFFFFFU) is rejected by start().
     */
    quint32 allowedVsockPeerCid() const;
    void setAllowedVsockPeerCid(quint32 cid);

    /**
     * Whether the server is currently listening (on either TCP or AF_VSOCK).
     */
    bool isListeningTransport() const;

    /**
     * The host address to listen on.
     *
     * Set this to an appropriate address for the server to listen on. Common
     * options are `0.0.0.0` to listen on all interfaces and accept all incoming
     * connections or `127.0.0.1` to only listen on the loopback interface and
     * only allow local connections.
     *
     * By default the address is set to QHostAddress::LocalHost
     */
    QHostAddress address() const;
    void setAddress(const QHostAddress &newAddress);

    /**
     * The port to listen on.
     *
     * By default this is set to 3389, which is the standard port used for RDP.
     */
    quint16 port() const;
    void setPort(quint16 newPort);

    /**
     * The list of users allowed to log in to the server.
     *
     * At least one user is required for the server to work.
     */
    QList<User> users() const;
    void setUsers(const QList<User> &users);
    void addUser(const User &user);

    /** Whether to authenticate against PAM for the user running the daemon
     */
    bool usePAMAuthentication() const;
    void setUsePAMAuthentication(bool usePAM);

    /**
     * The path of a certificate file to use for encrypting communications.
     *
     * This is required to be set to a valid file, as the RDP login process only
     * works over an encrypted connection.
     */
    std::filesystem::path tlsCertificate() const;
    void setTlsCertificate(const std::filesystem::path &newTlsCertificate);

    /**
     * The path of a certificate key to use for encrypting communications.
     *
     * This is required to be set to a valid file, as the RDP login process only
     * works over an encrypted connection.
     */
    std::filesystem::path tlsCertificateKey() const;
    void setTlsCertificateKey(const std::filesystem::path &newTlsCertificateKey);

    /**
     * Emitted whenever a new connection is started.
     *
     * \param connection The new connection that was just started.
     */
    Q_SIGNAL void newConnectionCreated(RdpConnection *connection);

protected:
    /**
     * Overridden from QTcpServer
     */
    void incomingConnection(qintptr handle) override;

private:
    friend class RdpConnection;
    rdp_settings *rdpSettings() const;

    class Private;
    const std::unique_ptr<Private> d;
};

}
