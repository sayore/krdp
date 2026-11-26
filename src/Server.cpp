// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "Server.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>

#include <QCoreApplication>
#include <QHash>
#include <QSocketNotifier>

#ifdef HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <freerdp/channels/channels.h>
#include <freerdp/freerdp.h>
#include <winpr/ssl.h>

#include "RdpConnection.h"

#include "krdp_logging.h"

using namespace KRdp;

namespace
{
#ifdef HAVE_LINUX_VM_SOCKETS_H
constexpr quint32 DefaultVsockBindCid = VMADDR_CID_ANY;
constexpr quint32 DefaultVsockPeerCid = VMADDR_CID_HOST;
#else
constexpr quint32 DefaultVsockBindCid = 0xFFFFFFFFU;
constexpr quint32 DefaultVsockPeerCid = 2U;
#endif
}

class KRDP_NO_EXPORT Server::Private
{
public:
    std::vector<std::unique_ptr<RdpConnection>> sessions;
    rdp_settings *settings = nullptr;

    Transport transport = Transport::Tcp;
    bool hyperVMode = false;
    bool inBandGreeterEnabled = false;
    quint32 vsockBindCid = DefaultVsockBindCid;
    quint32 allowedVsockPeerCid = DefaultVsockPeerCid;
    int vsockFd = -1;
    std::unique_ptr<QSocketNotifier> vsockNotifier;

    QHostAddress address = QHostAddress::LocalHost;
    quint16 port = 3389;

    QList<User> users;
    bool usePamAuthentication = false;

    mutable std::mutex authThrottleMutex;
    static constexpr qsizetype MaxTrackedAuthUsers = 256;
    int maxFailuresPerUser = 5;
    int authWindowMs = 300'000;
    int authLockoutMs = 30'000;
    QHash<QString, std::vector<std::chrono::steady_clock::time_point>> userAuthFailures;
    QHash<QString, std::chrono::steady_clock::time_point> userAuthLockedUntil;

    std::filesystem::path tlsCertificate;
    std::filesystem::path tlsCertificateKey;
};

Server::Server(QObject *parent)
    : QTcpServer(parent)
    , d(std::make_unique<Private>())
{
    winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);
    WTSRegisterWtsApiFunctionTable(FreeRDP_InitWtsApi());
}

Server::~Server()
{
    stop();
}

bool Server::start()
{
    if (!std::filesystem::exists(d->tlsCertificate) || !std::filesystem::exists(d->tlsCertificateKey)) {
        qCCritical(KRDP).nospace() << "A valid TLS certificate (" << QString::fromStdString(d->tlsCertificate.filename().string()) << ") and key ("
                                   << QString::fromStdString(d->tlsCertificateKey.filename().string()) << ") is required for the server to run!";
        return false;
    }

    if (d->transport == Transport::Tcp) {
        if (d->hyperVMode) {
            qCCritical(KRDP) << "Hyper-V VMConnect mode is strictly restricted to AF_VSOCK transport and cannot be enabled on TCP";
            return false;
        }
        if (d->inBandGreeterEnabled) {
            qCCritical(KRDP) << "In-band greeter mode is strictly restricted to AF_VSOCK Hyper-V VMConnect transport and cannot be enabled on TCP";
            return false;
        }

        if (!listen(d->address, d->port)) {
            // NOTE: We cannot use QTcpServer methods to get the server address and port because it won't initialize them if listen fails.
            qCCritical(KRDP) << "Unable to listen for connections on" << d->address << d->port;
            return false;
        }
    } else if (d->transport == Transport::Vsock) {
#ifdef HAVE_LINUX_VM_SOCKETS_H
        if (d->allowedVsockPeerCid == VMADDR_CID_ANY) {
            qCCritical(KRDP) << "Refusing to start AF_VSOCK listener with wildcard peer CID (VMADDR_CID_ANY)";
            return false;
        }

        const int fd = ::socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            qCCritical(KRDP) << "Unable to create AF_VSOCK socket:" << std::strerror(errno);
            return false;
        }

        const int reuse = 1;
        if (::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            qCWarning(KRDP) << "setsockopt(SO_REUSEADDR) on AF_VSOCK socket failed:" << std::strerror(errno);
        }

        sockaddr_vm addr{};
        addr.svm_family = AF_VSOCK;
        addr.svm_cid = d->vsockBindCid;
        addr.svm_port = d->port;

        if (::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0) {
            qCCritical(KRDP) << "Unable to bind AF_VSOCK socket on cid" << d->vsockBindCid << "port" << d->port << ":" << std::strerror(errno);
            ::close(fd);
            return false;
        }

        if (::listen(fd, 16) < 0) {
            qCCritical(KRDP) << "Unable to listen on AF_VSOCK socket on cid" << d->vsockBindCid << "port" << d->port << ":" << std::strerror(errno);
            ::close(fd);
            return false;
        }

        d->vsockFd = fd;
        d->vsockNotifier = std::make_unique<QSocketNotifier>(d->vsockFd, QSocketNotifier::Read, this);
        connect(d->vsockNotifier.get(), &QSocketNotifier::activated, this, [this]() {
            while (d->vsockFd >= 0) {
                sockaddr_vm peerAddr{};
                socklen_t peerLen = sizeof(peerAddr);
                const int clientFd = ::accept4(d->vsockFd, reinterpret_cast<sockaddr *>(&peerAddr), &peerLen, SOCK_CLOEXEC);
                if (clientFd < 0) {
                    if (errno == EAGAIN
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
                        || errno == EWOULDBLOCK
#endif
                    ) {
                        break;
                    }
                    if (errno == EINTR) {
                        continue;
                    }
                    qCWarning(KRDP) << "accept4() on AF_VSOCK failed:" << std::strerror(errno);
                    break;
                }

                if (peerLen < sizeof(sockaddr_vm) || peerAddr.svm_family != AF_VSOCK) {
                    qCWarning(KRDP) << "Rejecting non-AF_VSOCK peer on AF_VSOCK listener (family" << peerAddr.svm_family << ")";
                    ::close(clientFd);
                    continue;
                }

                if (peerAddr.svm_cid != d->allowedVsockPeerCid) {
                    qCWarning(KRDP) << "Rejecting unauthorized AF_VSOCK peer CID" << peerAddr.svm_cid << "(expected" << d->allowedVsockPeerCid << ")";
                    ::close(clientFd);
                    continue;
                }

                qCInfo(KRDP) << "Accepted AF_VSOCK connection from CID" << peerAddr.svm_cid << "port" << peerAddr.svm_port
                             << (d->hyperVMode ? "(Hyper-V VMConnect mode)" : "(standard TLS/NLA mode)");

                RdpConnection::TransportInfo info;
                info.transport = Transport::Vsock;
                info.vmConnectMode = d->hyperVMode;
                info.inBandGreeterEnabled = d->hyperVMode && d->inBandGreeterEnabled;
                info.vsockPeerCid = peerAddr.svm_cid;
                info.vsockPeerPort = peerAddr.svm_port;

                auto session = std::make_unique<RdpConnection>(this, clientFd, info);
                auto sessionPtr = session.get();
                connect(
                    sessionPtr,
                    &RdpConnection::stateChanged,
                    this,
                    [this, sessionPtr](RdpConnection::State state) {
                        if (state == RdpConnection::State::Closed) {
                            auto itr = std::find_if(d->sessions.begin(), d->sessions.end(), [sessionPtr](auto &session) {
                                return session.get() == sessionPtr;
                            });
                            if (itr == d->sessions.end()) {
                                return;
                            }
                            auto session = std::move(*itr);
                            d->sessions.erase(itr);
                        }
                    },
                    Qt::QueuedConnection);
                d->sessions.push_back(std::move(session));
                Q_EMIT newConnectionCreated(sessionPtr);
            }
        });
#else
        qCCritical(KRDP) << "AF_VSOCK transport requested, but KRdp was built without <linux/vm_sockets.h>";
        return false;
#endif
    }

    // FreeRDP3 tries to use a global instance of the settings object when
    // initializing a new peer. However, it seems to fail at actually creating a
    // global default instance. So create one here and use that.
    d->settings = freerdp_settings_new(FREERDP_SETTINGS_SERVER_MODE);

    if (d->transport == Transport::Vsock) {
        qCInfo(KRDP) << "Listening for AF_VSOCK connections on cid" << d->vsockBindCid << "port" << d->port << "allowedPeerCid" << d->allowedVsockPeerCid
                     << "hyperVMode" << d->hyperVMode;
    } else {
        qCDebug(KRDP) << "Listening for connections on" << serverAddress() << serverPort();
    }
    return true;
}

void Server::stop()
{
    if (d->vsockNotifier) {
        d->vsockNotifier->setEnabled(false);
        d->vsockNotifier.reset();
    }
#ifdef HAVE_LINUX_VM_SOCKETS_H
    if (d->vsockFd >= 0) {
        ::close(d->vsockFd);
        d->vsockFd = -1;
    }
#endif

    close();

    if (d->settings) {
        freerdp_settings_free(d->settings);
        d->settings = nullptr;
    }
}

Server::Transport Server::transport() const
{
    return d->transport;
}

void Server::setTransport(Transport newTransport)
{
    d->transport = newTransport;
}

bool Server::hyperVMode() const
{
    return d->hyperVMode;
}

void Server::setHyperVMode(bool enabled)
{
    d->hyperVMode = enabled;
}

bool Server::inBandGreeterEnabled() const
{
    return d->inBandGreeterEnabled;
}

void Server::setInBandGreeterEnabled(bool enabled)
{
    d->inBandGreeterEnabled = enabled;
}

quint32 Server::vsockBindCid() const
{
    return d->vsockBindCid;
}

void Server::setVsockBindCid(quint32 cid)
{
    d->vsockBindCid = cid;
}

quint32 Server::allowedVsockPeerCid() const
{
    return d->allowedVsockPeerCid;
}

void Server::setAllowedVsockPeerCid(quint32 cid)
{
    d->allowedVsockPeerCid = cid;
}

bool Server::isListeningTransport() const
{
    if (d->transport == Transport::Vsock) {
        return d->vsockFd >= 0;
    }
    return isListening();
}

QHostAddress Server::address() const
{
    return d->address;
}

void Server::setAddress(const QHostAddress &newAddress)
{
    if (newAddress == d->address) {
        return;
    }

    d->address = newAddress;
}

quint16 Server::port() const
{
    return d->port;
}

void Server::setPort(quint16 newPort)
{
    if (newPort == d->port) {
        return;
    }

    d->port = newPort;
}

QList<User> KRdp::Server::users() const
{
    return d->users;
}

void KRdp::Server::setUsers(const QList<User> &users)
{
    d->users = users;
}

void KRdp::Server::addUser(const User &user)
{
    d->users.append(user);
}

bool Server::usePAMAuthentication() const
{
    return d->usePamAuthentication;
}

void Server::setUsePAMAuthentication(bool usePAM)
{
    d->usePamAuthentication = usePAM;
}

void Server::setAuthThrottlePolicy(int maxFailuresPerUser, int windowMs, int lockoutMs)
{
    std::lock_guard lock(d->authThrottleMutex);
    d->maxFailuresPerUser = std::max(1, maxFailuresPerUser);
    d->authWindowMs = std::max(100, windowMs);
    d->authLockoutMs = std::max(100, lockoutMs);
    d->userAuthFailures.clear();
    d->userAuthLockedUntil.clear();
}

bool Server::isAuthAttemptAllowed(const QString &username) const
{
    const QString key = username.section(QLatin1Char('\\'), -1).trimmed().toLower();
    if (key.isEmpty()) {
        return true;
    }
    const auto now = std::chrono::steady_clock::now();

    std::lock_guard lock(d->authThrottleMutex);
    const auto it = d->userAuthLockedUntil.constFind(key);
    if (it != d->userAuthLockedUntil.cend()) {
        if (now < it.value()) {
            return false;
        }
        d->userAuthLockedUntil.erase(it);
    }
    return true;
}

void Server::recordAuthFailure(const QString &username)
{
    const QString key = username.section(QLatin1Char('\\'), -1).trimmed().toLower();
    if (key.isEmpty()) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();

    std::lock_guard lock(d->authThrottleMutex);
    const auto window = std::chrono::milliseconds(d->authWindowMs);
    const auto lockout = std::chrono::milliseconds(d->authLockoutMs);
    const auto cutoff = now - window;

    // Prune expired lockout & failure entries to prevent unbounded memory growth.
    for (auto it = d->userAuthLockedUntil.begin(); it != d->userAuthLockedUntil.end();) {
        if (now >= it.value()) {
            it = d->userAuthLockedUntil.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = d->userAuthFailures.begin(); it != d->userAuthFailures.end();) {
        auto &vec = it.value();
        vec.erase(std::remove_if(vec.begin(),
                                 vec.end(),
                                 [cutoff](const auto &tp) {
                                     return tp < cutoff;
                                 }),
                  vec.end());
        if (vec.empty()) {
            it = d->userAuthFailures.erase(it);
        } else {
            ++it;
        }
    }

    // Enforce strict hard ceiling on tracked accounts (evict oldest entry if full).
    if (!d->userAuthFailures.contains(key) && d->userAuthFailures.size() >= Private::MaxTrackedAuthUsers) {
        auto oldestIt = d->userAuthFailures.begin();
        for (auto it = d->userAuthFailures.begin(); it != d->userAuthFailures.end(); ++it) {
            if (!it.value().empty() && (oldestIt.value().empty() || it.value().back() < oldestIt.value().back())) {
                oldestIt = it;
            }
        }
        d->userAuthFailures.erase(oldestIt);
    }

    auto &failures = d->userAuthFailures[key];
    failures.push_back(now);
    if (static_cast<int>(failures.size()) >= d->maxFailuresPerUser) {
        if (!d->userAuthLockedUntil.contains(key) && d->userAuthLockedUntil.size() >= Private::MaxTrackedAuthUsers) {
            auto earliestIt = d->userAuthLockedUntil.begin();
            for (auto it = d->userAuthLockedUntil.begin(); it != d->userAuthLockedUntil.end(); ++it) {
                if (it.value() < earliestIt.value()) {
                    earliestIt = it;
                }
            }
            d->userAuthLockedUntil.erase(earliestIt);
        }
        d->userAuthLockedUntil[key] = now + lockout;
        d->userAuthFailures.remove(key);
        qCWarning(KRDP) << "Cross-connection authentication lockout triggered for bucket" << key << "for" << d->authLockoutMs << "ms";
    }
}

void Server::recordAuthSuccess(const QString &username)
{
    const QString key = username.section(QLatin1Char('\\'), -1).trimmed().toLower();
    std::lock_guard lock(d->authThrottleMutex);
    if (!key.isEmpty()) {
        d->userAuthFailures.remove(key);
        d->userAuthLockedUntil.remove(key);
    }
}

qsizetype Server::trackedAuthThrottleEntries() const
{
    std::lock_guard lock(d->authThrottleMutex);
    return d->userAuthFailures.size() + d->userAuthLockedUntil.size();
}

std::filesystem::path Server::tlsCertificate() const
{
    return d->tlsCertificate;
}

void Server::setTlsCertificate(const std::filesystem::path &newTlsCertificate)
{
    if (newTlsCertificate == d->tlsCertificate) {
        return;
    }

    d->tlsCertificate = newTlsCertificate;
}

std::filesystem::path Server::tlsCertificateKey() const
{
    return d->tlsCertificateKey;
}

void Server::setTlsCertificateKey(const std::filesystem::path &newTlsCertificateKey)
{
    if (newTlsCertificateKey == d->tlsCertificateKey) {
        return;
    }

    d->tlsCertificateKey = newTlsCertificateKey;
}

void Server::incomingConnection(qintptr handle)
{
    auto session = std::make_unique<RdpConnection>(this, handle);
    auto sessionPtr = session.get();
    // queued: signal comes from the run thread, and it keeps the erase below from destroying the sender mid-emission
    connect(
        sessionPtr,
        &RdpConnection::stateChanged,
        this,
        [this, sessionPtr](RdpConnection::State state) {
            if (state == RdpConnection::State::Closed) {
                auto itr = std::find_if(d->sessions.begin(), d->sessions.end(), [sessionPtr](auto &session) {
                    return session.get() == sessionPtr;
                });
                if (itr == d->sessions.end()) {
                    return;
                }
                // extracted before erasing: ~RdpConnection can spin a nested event loop (KScreen calls
                // from destroyed() handlers) that re-enters this vector, so destroy it once consistent again
                auto session = std::move(*itr);
                d->sessions.erase(itr);
            }
        },
        Qt::QueuedConnection);
    d->sessions.push_back(std::move(session));
    Q_EMIT newConnectionCreated(sessionPtr);
}

rdp_settings *Server::rdpSettings() const
{
    return d->settings;
}

#include "moc_Server.cpp"
