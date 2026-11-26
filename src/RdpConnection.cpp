// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// This file is roughly based on grd-session-rdp.c from gnome-remote-desktop,
// which is:
//
// SPDX-FileCopyrightText: 2020-2023 Pascal Nowack
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include "RdpConnection.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <optional>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
#endif

#include <QHostAddress>
#include <QStandardPaths>
#include <QTcpSocket>
#include <QTemporaryFile>
#include <QThread>

#include <freerdp/channels/wtsvc.h>
#include <freerdp/freerdp.h>
#include <freerdp/server/cliprdr.h>

#include <freerdp/channels/drdynvc.h>
#include <freerdp/channels/rdpsnd.h>

#include "AbstractSession.h"
#include "AudioInputStream.h"
#include "AudioStream.h"
#include "Clipboard.h"
#include "Cursor.h"
#include "DisplayControl.h"
#include "InBandGreeter.h"
#include "InputHandler.h"
#include "NetworkDetection.h"
#include "PeerContext_p.h"
#include "Server.h"
#include "VideoStream.h"

#include <KUser>

#include "krdp_logging.h"

namespace fs = std::filesystem;

namespace KRdp
{

/**
 * Create the "sam" file used by FreeRDP for reading username and password
 * information. It hashes the password in the appropriate format and writes that
 * along with the username to the provided temporary file.
 */
static bool createSamFile(QTemporaryFile &file, const QList<User> &users)
{
    auto runtimePath = fs::path(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation).toStdString());

    auto path = runtimePath / "krdp";
    fs::create_directories(path);

    file.setFileTemplate(QString::fromStdString(path / "rdp-sam-XXXXXX"));
    if (!file.open()) {
        qCWarning(KRDP) << "Could not open SAM file";
        return false;
    }

    QString data;

    for (const auto &user : users) {
        auto username = user.name.section(QLatin1Char('\\'), -1);
        if (RdpConnection::isDisallowedLoginUser(username) || user.password.isEmpty()) {
            qCWarning(KRDP) << "Skipping disallowed or empty-password user in SAM file:" << username;
            continue;
        }
        auto password = user.password.toUtf8();

        std::array<uint8_t, 16> hash;
        NTOWFv1A((LPSTR)password.data(), password.size(), hash.data());

        auto entry = QStringLiteral("%1:::").arg(username);
        for (int i = 0; i < 16; ++i) {
            entry.append(QStringLiteral("%1").arg(hash[i], 2, 16, QLatin1Char('0')));
        }
        entry.append(QStringLiteral(":::\n"));
        data.append(entry);
    }

    file.write(data.toUtf8());
    file.close();

    return true;
}

#include <security/pam_appl.h>

typedef struct {
    QByteArray user;
    QByteArray password;
} RDPConnectionAuthData;

typedef struct {
    pam_handle_t *handle;
    struct pam_conv pamc;
    RDPConnectionAuthData appdata;
} RdpConnectionPamHandle;

static int pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int pam_status = PAM_CONV_ERR;
    RDPConnectionAuthData *appdata = NULL;
    struct pam_response *response = NULL;
    WINPR_ASSERT(num_msg >= 0);
    appdata = (RDPConnectionAuthData *)appdata_ptr;
    WINPR_ASSERT(appdata);

    if (!(response = (struct pam_response *)calloc((size_t)num_msg, sizeof(struct pam_response))))
        return PAM_BUF_ERR;

    for (int index = 0; index < num_msg; index++) {
        switch (msg[index]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            response[index].resp = _strdup(appdata->user.constData());

            if (!response[index].resp)
                goto out_fail;

            response[index].resp_retcode = PAM_SUCCESS;
            break;

        case PAM_PROMPT_ECHO_OFF:
            response[index].resp = _strdup(appdata->password.constData());

            if (!response[index].resp)
                goto out_fail;

            response[index].resp_retcode = PAM_SUCCESS;
            break;

        default:
            pam_status = PAM_CONV_ERR;
            goto out_fail;
        }
    }

    *resp = response;
    return PAM_SUCCESS;
out_fail:

    for (int index = 0; index < num_msg; ++index) {
        if (response[index].resp) {
            memset(response[index].resp, 0, strlen(response[index].resp));
            free(response[index].resp);
        }
    }

    memset(response, 0, sizeof(struct pam_response) * (size_t)num_msg);
    free(response);
    *resp = NULL;
    return pam_status;
}

static int pamAuthenticate(const QString &user, const QString &password)
{
    if (user.isEmpty() || password.isEmpty() || RdpConnection::isDisallowedLoginUser(user)) {
        return -1;
    }

    int pam_status = 0;
    RdpConnectionPamHandle info = {};

    info.appdata.user = user.toUtf8();
    info.appdata.password = password.toUtf8();
    info.pamc.conv = &pam_conv;
    info.pamc.appdata_ptr = &info.appdata;

    auto cleanup = [&]() {
        if (info.handle) {
            pam_end(info.handle, pam_status);
            info.handle = nullptr;
        }
        if (!info.appdata.password.isEmpty()) {
            explicit_bzero(info.appdata.password.data(), static_cast<size_t>(info.appdata.password.size()));
            info.appdata.password.clear();
        }
    };

    pam_status = pam_start("login", 0, &info.pamc, &info.handle);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_start failure:" << pam_strerror(info.handle, pam_status);
        cleanup();
        return -1;
    }

    pam_status = pam_authenticate(info.handle, 0);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_authenticate failure:" << pam_strerror(info.handle, pam_status);
        cleanup();
        return -1;
    }

    pam_status = pam_acct_mgmt(info.handle, 0);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_acct_mgmt failure:" << pam_strerror(info.handle, pam_status);
        cleanup();
        return -1;
    }

    cleanup();
    return 1;
}

/**
 * FreeRDP callback for the capabilities event.
 */
BOOL peerCapabilities(freerdp_peer *peer)
{
    auto context = contextForPeer(peer);
    if (context->connection->onCapabilities()) {
        return TRUE;
    }

    return FALSE;
}

/**
 * FreeRDP callback for the post connect event.
 */
BOOL peerPostConnect(freerdp_peer *peer)
{
    auto context = contextForPeer(peer);
    if (context->connection->onPostConnect()) {
        return TRUE;
    }

    return FALSE;
}

/**
 * FreeRDP callback for the activate event.
 */
BOOL peerActivate(freerdp_peer *peer)
{
    auto context = reinterpret_cast<PeerContext *>(peer->context);
    if (context->connection->onActivate()) {
        return TRUE;
    }

    return FALSE;
}

BOOL suppressOutput(rdpContext *context, uint8_t allow, const RECTANGLE_16 *)
{
    auto peerContext = reinterpret_cast<PeerContext *>(context);
    if (peerContext->connection->onSuppressOutput(allow)) {
        return TRUE;
    }

    return FALSE;
}

class KRDP_NO_EXPORT RdpConnection::Private
{
public:
    Server *server = nullptr;

    std::atomic<State> state{State::Initial};
    std::atomic<AuthState> authState{AuthState::Unauthenticated};
    mutable std::mutex authUserMutex;
    QString authenticatedUser;
    mutable std::atomic<bool> authenticatedViaPam{false};
    bool qualitySeeded = false;
    bool greeterStarted = false;
    int activateCount = 0;

    qintptr socketHandle;
    TransportInfo transportInfo;

    std::unique_ptr<InputHandler> inputHandler;
    std::unique_ptr<InBandGreeter> inBandGreeter;
    std::unique_ptr<AudioInputStream> audioInputStream;
    std::unique_ptr<AudioStream> audioStream;
    std::unique_ptr<VideoStream> videoStream;
    std::unique_ptr<Cursor> cursor;
    std::unique_ptr<NetworkDetection> networkDetection;
    std::unique_ptr<Clipboard> clipboard;
    std::unique_ptr<DisplayControl> displayControl;

    freerdp_peer *peer = nullptr;

    std::jthread thread;

    // Manual-reset event the run thread waits on alongside the peer transport
    // handles. Signalling it wakes the thread for teardown without any protocol
    // I/O on the peer from the calling thread.
    HANDLE stopEvent = nullptr;

    // Ask the run thread to finish, from any thread. It owns the peer and closes
    // it as it exits, so callers never touch the peer themselves.
    void requestStop()
    {
        thread.request_stop();
        if (stopEvent) {
            SetEvent(stopEvent);
        }
    }

    QTemporaryFile samFile;
};

RdpConnection::RdpConnection(Server *server, qintptr socketHandle)
    : RdpConnection(server, socketHandle, TransportInfo{})
{
}

RdpConnection::RdpConnection(Server *server, qintptr socketHandle, const TransportInfo &transportInfo)
    : QObject(nullptr)
    , d(std::make_unique<Private>())
{
    d->server = server;
    d->socketHandle = socketHandle;
    d->transportInfo = transportInfo;

    d->inputHandler = std::make_unique<InputHandler>(this);
    d->inBandGreeter = std::make_unique<InBandGreeter>(this);
    d->videoStream = std::make_unique<VideoStream>(this);
    connect(d->videoStream.get(), &VideoStream::closed, this, [this]() {
        const State cur = state();
        if (cur == State::Running || cur == State::Streaming) {
            qCDebug(KRDP) << "Video stream closed, closing session";
            d->requestStop();
        }
    });
    connect(d->videoStream.get(), &VideoStream::capsConfirmed, d->inBandGreeter.get(), [this]() {
        if (d->authState.load(std::memory_order_acquire) == AuthState::PendingInBandGreeter) {
            d->inBandGreeter->requestRedraw();
        }
    });
    d->cursor = std::make_unique<Cursor>(this);
    d->networkDetection = std::make_unique<NetworkDetection>(this);
    d->clipboard = std::make_unique<Clipboard>(this);
    d->audioStream = std::make_unique<AudioStream>(this);
    d->audioInputStream = std::make_unique<AudioInputStream>(this);
    d->displayControl = std::make_unique<DisplayControl>(this);

    connect(d->inputHandler.get(), &InputHandler::inputEvent, d->inBandGreeter.get(), [this](const std::shared_ptr<QInputEvent> &event) {
        if (d->authState.load(std::memory_order_acquire) == AuthState::PendingInBandGreeter) {
            d->inBandGreeter->handleInputEvent(event);
        }
    });
    connect(d->displayControl.get(), &DisplayControl::requestedScreenSizeChanged, d->inBandGreeter.get(), [this](const QSize &size) {
        if (d->authState.load(std::memory_order_acquire) == AuthState::PendingInBandGreeter) {
            d->inBandGreeter->setScreenSize(size);
        }
    });
    connect(d->inBandGreeter.get(), &InBandGreeter::frameReady, this, [this](const QImage &image) {
        if (d->authState.load(std::memory_order_acquire) != AuthState::PendingInBandGreeter) {
            return;
        }
        VideoFrame frame;
        frame.size = image.size();
        frame.image = image;
        frame.damage = QRegion(QRect(QPoint(0, 0), image.size()));
        d->videoStream->queueFrame(frame);
    });
    connect(d->inBandGreeter.get(), &InBandGreeter::authenticated, this, [this](const QString &user) {
        {
            std::lock_guard lock(d->authUserMutex);
            d->authenticatedUser = user.section(QLatin1Char('\\'), -1).trimmed();
        }
        qCInfo(KRDP) << "Transitioning connection from PendingInBandGreeter to Authenticated for user" << authenticatedUser();
        setAuthState(AuthState::Authenticated);
        d->videoStream->onSessionAuthenticated();
    });
    connect(d->inBandGreeter.get(), &InBandGreeter::failedAndClose, this, [this](const QString &reason) {
        qCWarning(KRDP) << "Closing session from in-band greeter:" << reason;
        close(CloseReason::None);
    });

    QMetaObject::invokeMethod(this, &RdpConnection::initialize, Qt::QueuedConnection);
}

RdpConnection::~RdpConnection()
{
    // The run thread owns the peer transport and closes it as it exits, so just
    // wake it (stopEvent) and join before we free. Closing the peer here, while
    // the run thread still reads the same transport, races inside FreeRDP and
    // crashes on shutdown.
    if (d->thread.joinable()) {
        d->requestStop();
        d->thread.join();
    } else if (d->peer && state() != State::Closed) {
        // The run thread was never started (peer set up but initialize failed):
        // nothing else touches the peer, so close it here before freeing.
        d->peer->Close(d->peer);
    }

    if (d->peer) {
        // freerdp_peer_free() does not free the context allocated by
        // freerdp_peer_context_new_ex().
        freerdp_peer_context_free(d->peer);
        freerdp_peer_free(d->peer);
    }

    if (d->stopEvent) {
        CloseHandle(d->stopEvent);
    }
}

RdpConnection::State RdpConnection::state() const
{
    return d->state.load(std::memory_order_acquire);
}

void RdpConnection::setState(KRdp::RdpConnection::State newState)
{
    const State prev = d->state.exchange(newState, std::memory_order_acq_rel);
    if (prev == newState) {
        return;
    }

    Q_EMIT stateChanged(newState);
}

RdpConnection::AuthState RdpConnection::authState() const
{
    return d->authState.load(std::memory_order_acquire);
}

bool RdpConnection::isAuthenticated() const
{
    return d->authState.load(std::memory_order_acquire) == AuthState::Authenticated;
}

QString RdpConnection::authenticatedUser() const
{
    std::lock_guard lock(d->authUserMutex);
    return d->authenticatedUser;
}

bool RdpConnection::authenticatedViaPam() const
{
    return d->authenticatedViaPam.load(std::memory_order_acquire);
}

void RdpConnection::setAuthState(AuthState newAuthState)
{
    const AuthState prev = d->authState.exchange(newAuthState, std::memory_order_acq_rel);
    if (prev == newAuthState) {
        return;
    }
    Q_EMIT authStateChanged(newAuthState);
    const bool wasAuth = (prev == AuthState::Authenticated);
    const bool isAuth = (newAuthState == AuthState::Authenticated);
    if (wasAuth != isAuth) {
        Q_EMIT authenticatedChanged(isAuth);
    }
}

InBandGreeter *RdpConnection::inBandGreeter() const
{
    return d->inBandGreeter.get();
}

void RdpConnection::startInBandGreeter()
{
    if (d->greeterStarted || d->authState.load(std::memory_order_acquire) != AuthState::PendingInBandGreeter) {
        return;
    }
    d->greeterStarted = true;
    QSize initialSize(1280, 720);
    quint32 keyboardLayout = 0;
    if (d->peer && d->peer->context && d->peer->context->settings) {
        auto *settings = d->peer->context->settings;
        const int w = static_cast<int>(freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth));
        const int h = static_cast<int>(freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight));
        if (w >= 640 && h >= 480) {
            initialSize = QSize(w, h);
        }
        keyboardLayout = freerdp_settings_get_uint32(settings, FreeRDP_KeyboardLayout);
    }
    QString defaultUser = KUser().loginName();
    if (defaultUser == QStringLiteral("plasmalogin") || isDisallowedLoginUser(defaultUser)) {
        defaultUser.clear();
    }
    d->inBandGreeter->setKeyboardLayout(keyboardLayout);
    d->inBandGreeter->start(initialSize, defaultUser);
}

bool RdpConnection::verifyGuestCredentials(const QString &username, const QString &password) const
{
    const QString normalized = username.section(QLatin1Char('\\'), -1).trimmed();
    const QString sessionOwner = KUser().loginName();
    const auto configuredUsers = d->server->users();

    bool isKnownAccount = false;
    if (!normalized.isEmpty() && !isDisallowedLoginUser(normalized)) {
        if (d->server->usePAMAuthentication() && (normalized == sessionOwner || sessionOwner == QStringLiteral("plasmalogin"))) {
            isKnownAccount = true;
        } else {
            for (const auto &user : configuredUsers) {
                if (!user.password.isEmpty() && !isDisallowedLoginUser(user.name) && user.name == normalized) {
                    isKnownAccount = true;
                    break;
                }
            }
        }
    }

    // Route unknown or disallowed usernames (e.g. "root" or random probing) into a
    // dedicated shared throttle bucket so they are rate-limited without growing maps
    // unboundedly or locking out legitimate users via cross-user DoS.
    const QString throttleBucket = isKnownAccount ? normalized : QStringLiteral("<unknown-or-disallowed>");

    if (!d->server->isAuthAttemptAllowed(throttleBucket)) {
        qCWarning(KRDP) << "Rejecting authentication attempt for bucket" << throttleBucket << "(cross-connection rate limit active)";
        return false;
    }

    if (normalized.isEmpty() || password.isEmpty() || isDisallowedLoginUser(normalized)) {
        d->server->recordAuthFailure(throttleBucket);
        return false;
    }

    if (d->server->usePAMAuthentication()) {
        qCDebug(KRDP) << "Attempting authenticating user with PAM";
        if (normalized == sessionOwner || sessionOwner == QStringLiteral("plasmalogin")) {
            if (pamAuthenticate(normalized, password) >= 0) {
                qCDebug(KRDP) << "PAM authentication succeeded for user" << normalized;
                d->authenticatedViaPam.store(true, std::memory_order_release);
                d->server->recordAuthSuccess(throttleBucket);
                return true;
            }
        }
    }

    for (const auto &user : configuredUsers) {
        if (user.password.isEmpty() || isDisallowedLoginUser(user.name)) {
            continue;
        }
        if (user.name == normalized && user.password == password) {
            qCDebug(KRDP) << "User" << normalized << "authenticated successfully";
            d->authenticatedViaPam.store(false, std::memory_order_release);
            d->server->recordAuthSuccess(throttleBucket);
            return true;
        }
    }

    d->server->recordAuthFailure(throttleBucket);
    return false;
}

void RdpConnection::close(RdpConnection::CloseReason reason)
{
    if (state() == State::Closed) {
        return;
    }

    switch (reason) {
    case CloseReason::VideoInitFailed:
        freerdp_set_error_info(d->peer->context->rdp, ERRINFO_GRAPHICS_SUBSYSTEM_FAILED);
        break;
    case CloseReason::None:
        break;
    }

    // Hand teardown to the run thread; it owns the peer transport and closes it
    // as it exits. This is called from the main thread (SessionController) and
    // from video-encoding threads (VideoStream), so it must not drive the peer
    // directly - that would race with the run thread reading the same transport.
    d->requestStop();
}

InputHandler *RdpConnection::inputHandler() const
{
    return d->inputHandler.get();
}

KRdp::VideoStream *RdpConnection::videoStream() const
{
    return d->videoStream.get();
}

Cursor *RdpConnection::cursor() const
{
    return d->cursor.get();
}

Clipboard *RdpConnection::clipboard() const
{
    return d->clipboard.get();
}

AudioStream *RdpConnection::audioStream() const
{
    return d->audioStream.get();
}

AudioInputStream *RdpConnection::audioInputStream() const
{
    return d->audioInputStream.get();
}

DisplayControl *RdpConnection::displayControl() const
{
    return d->displayControl.get();
}

NetworkDetection *RdpConnection::networkDetection() const
{
    return d->networkDetection.get();
}

bool RdpConnection::isDisallowedLoginUser(const QString &username)
{
    const QString normalized = username.section(QLatin1Char('\\'), -1).trimmed();
    if (normalized.isEmpty()) {
        return true;
    }
    if (normalized.compare(QStringLiteral("root"), Qt::CaseInsensitive) == 0) {
        return true;
    }
    const KUser user(normalized);
    if (user.isValid() && user.userId().nativeId() == 0) {
        return true;
    }
    return false;
}

void RdpConnection::initialize()
{
    setState(State::Starting);

    if (d->transportInfo.vmConnectMode) {
        bool verifiedVsockHostPeer = false;
#ifdef KRDP_VMCONNECT_TEST_HARNESS
        // Compile-time-only test harness seam for autotests/vmconnectauthtest (NEVER defined in libKRdp.so or krdpserver).
        if (d->transportInfo.transport == Server::Transport::Vsock && d->transportInfo.vsockPeerCid == d->server->allowedVsockPeerCid()) {
            verifiedVsockHostPeer = true;
        }
#elif defined(HAVE_LINUX_VM_SOCKETS_H)
        if (d->transportInfo.transport == Server::Transport::Vsock && d->server->transport() == Server::Transport::Vsock && d->server->hyperVMode()) {
            sockaddr_storage peerStorage{};
            socklen_t peerLen = sizeof(peerStorage);
            if (::getpeername(static_cast<int>(d->socketHandle), reinterpret_cast<sockaddr *>(&peerStorage), &peerLen) == 0 && peerStorage.ss_family == AF_VSOCK
                && peerLen >= sizeof(sockaddr_vm)) {
                const auto *peerVm = reinterpret_cast<const sockaddr_vm *>(&peerStorage);
                if (peerVm->svm_cid == d->server->allowedVsockPeerCid()) {
                    verifiedVsockHostPeer = true;
                } else {
                    qCWarning(KRDP) << "Refusing Hyper-V VMConnect mode for unauthorized AF_VSOCK peer CID" << peerVm->svm_cid << "(expected"
                                    << d->server->allowedVsockPeerCid() << ")";
                }
            } else {
                qCWarning(KRDP) << "Refusing Hyper-V VMConnect mode: peer socket is not a verified AF_VSOCK connection";
            }
        } else {
            qCWarning(KRDP) << "Refusing Hyper-V VMConnect mode outside AF_VSOCK transport";
        }
#else
        qCWarning(KRDP) << "Refusing Hyper-V VMConnect mode: built without AF_VSOCK support";
#endif
        if (!verifiedVsockHostPeer) {
            if (d->socketHandle >= 0) {
                ::close(static_cast<int>(d->socketHandle));
                d->socketHandle = -1;
            }
            setState(State::Closed);
            return;
        }
    }

    d->peer = freerdp_peer_new(d->socketHandle);
    if (!d->peer) {
        qCWarning(KRDP) << "Failed to create peer";
        if (d->socketHandle >= 0) {
            ::close(static_cast<int>(d->socketHandle));
            d->socketHandle = -1;
        }
        setState(State::Closed);
        return;
    }

    if (d->transportInfo.transport == Server::Transport::Vsock) {
        d->peer->local = TRUE;
        std::snprintf(d->peer->hostname, sizeof(d->peer->hostname), "vsock://%u:%u", d->transportInfo.vsockPeerCid, d->transportInfo.vsockPeerPort);
    }

    // Create an instance of our custom PeerContext extended context as context
    // rather than the plain rdpContext.
    d->peer->ContextSize = sizeof(PeerContext);
    d->peer->ContextNew = (psPeerContextNew)newPeerContext;
    d->peer->ContextFree = (psPeerContextFree)freePeerContext;

    auto result = freerdp_peer_context_new_ex(d->peer, d->server->rdpSettings());
    if (!result) {
        qCWarning(KRDP) << "Failed to create peer context";
        setState(State::Closed);
        return;
    }

    auto context = reinterpret_cast<PeerContext *>(d->peer->context);
    context->connection = this;

    auto settings = d->peer->context->settings;

    const bool usePamAuthentication = d->server->usePAMAuthentication();

    if (!usePamAuthentication && !d->transportInfo.vmConnectMode) {
        if (!createSamFile(d->samFile, d->server->users())) {
            qFatal("Failed to create SAM database");
            return;
        }

        if (!freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, d->samFile.fileName().toUtf8().constData())) {
            qFatal("Failed to set SAM database");
            return;
        }
    }

    auto certificate = freerdp_certificate_new_from_file(d->server->tlsCertificate().string().data());
    if (!certificate) {
        qCWarning(KRDP) << "Could not read certificate file" << d->server->tlsCertificate().string();
        setState(State::Closed);
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, certificate, 1);

    auto key = freerdp_key_new_from_file(d->server->tlsCertificateKey().string().data());
    if (!key) {
        qCWarning(KRDP) << "Could not read certificate file" << d->server->tlsCertificate().string();
        setState(State::Closed);
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1);

    if (d->transportInfo.vmConnectMode) {
        // Hyper-V Enhanced Session over HvSocket (AF_VSOCK, host CID 2):
        // vmms.exe terminates TLS/CredSSP between vmconnect.exe and the host,
        // then sends plaintext MCS Connect Initial immediately after RDP_NEG_RSP.
        // Enable FreeRDP_VmConnectMode with PROTOCOL_SSL (not PROTOCOL_HYBRID,
        // which would fail FreeRDP peer.c:831 when NLA is skipped) and enforce
        // guest user authentication strictly in onPostConnect().
        freerdp_settings_set_bool(settings, FreeRDP_VmConnectMode, true);
        freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, false);
        freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, true);
        freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, false);
        freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, false);
        freerdp_settings_set_bool(settings, FreeRDP_RdstlsSecurity, false);
        freerdp_settings_set_bool(settings, FreeRDP_RestrictedAdminModeSupported, true);
    } else {
        freerdp_settings_set_bool(settings, FreeRDP_VmConnectMode, false);
        freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, false);
        freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, usePamAuthentication);
        freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, !usePamAuthentication);
        freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, false);
        // We do not implement RDSTLS, don't rely on FreeRDP's default for it
        freerdp_settings_set_bool(settings, FreeRDP_RdstlsSecurity, false);
    }

    freerdp_settings_set_uint32(settings, FreeRDP_OsMajorType, OSMAJORTYPE_UNIX);
    // PSEUDO_XSERVER is apparently required for things to work properly.
    freerdp_settings_set_uint32(settings, FreeRDP_OsMinorType, OSMINORTYPE_PSEUDO_XSERVER);

    freerdp_settings_set_bool(settings, FreeRDP_AudioPlayback, true);
    freerdp_settings_set_bool(settings, FreeRDP_AudioCapture, true);

    freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32);

    freerdp_settings_set_bool(settings, FreeRDP_SupportGraphicsPipeline, true);
    freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444v2, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxH264, !VideoStream::h264Disabled());
    freerdp_settings_set_bool(settings, FreeRDP_GfxProgressive, true);
    freerdp_settings_set_bool(settings, FreeRDP_SmartSizing, true);

    freerdp_settings_set_bool(settings, FreeRDP_GfxSmallCache, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxThinClient, false);
    freerdp_settings_set_bool(settings, FreeRDP_SupportDynamicChannels, true);

    freerdp_settings_set_bool(settings, FreeRDP_HasExtendedMouseEvent, true);
    freerdp_settings_set_bool(settings, FreeRDP_HasRelativeMouseEvent, false);
    freerdp_settings_set_bool(settings, FreeRDP_HasHorizontalWheel, true);
    freerdp_settings_set_bool(settings, FreeRDP_UnicodeInput, true);

    // TODO: Implement network performance detection
    freerdp_settings_set_bool(settings, FreeRDP_NetworkAutoDetect, true);

    freerdp_settings_set_bool(settings, FreeRDP_RefreshRect, true);
    freerdp_settings_set_bool(settings, FreeRDP_RemoteConsoleAudio, false);
    freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, false);
    freerdp_settings_set_bool(settings, FreeRDP_NSCodec, false);
    freerdp_settings_set_bool(settings, FreeRDP_FrameMarkerCommandEnabled, true);
    freerdp_settings_set_bool(settings, FreeRDP_SurfaceFrameMarkerEnabled, true);

    freerdp_settings_set_bool(settings, FreeRDP_SupportMonitorLayoutPdu, true);
    freerdp_settings_set_bool(settings, FreeRDP_SupportDisplayControl, true);

    d->peer->Capabilities = peerCapabilities;
    d->peer->Activate = peerActivate;
    d->peer->PostConnect = peerPostConnect;

    d->peer->context->update->SuppressOutput = suppressOutput;

    d->inputHandler->initialize(d->peer->context->input);
    context->inputHandler = d->inputHandler.get();

    context->networkDetection = d->networkDetection.get();
    d->networkDetection->initialize();

    if (!d->peer->Initialize(d->peer)) {
        qCWarning(KRDP) << "Unable to initialize peer";
        return;
    }

    qCDebug(KRDP) << "Session setup completed, start processing...";

    // Manual-reset event the run thread waits on, so teardown can wake it
    // without protocol I/O on the peer. Created before the thread starts.
    d->stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    // Perform actual communication on a separate thread.
    d->thread = std::jthread(std::bind(&RdpConnection::run, this, std::placeholders::_1));
    pthread_setname_np(d->thread.native_handle(), "krdp_session");
}

void RdpConnection::run(std::stop_token stopToken)
{
    auto context = reinterpret_cast<PeerContext *>(d->peer->context);
    auto channelEvent = WTSVirtualChannelManagerGetEventHandle(context->virtualChannelManager);
    BYTE lastDrdynvcState = 0xFF;
    bool lastDrdynvcJoined = false;
    bool audioInitAttempted = false;
    bool audioInputInitAttempted = false;
    setState(State::Running);

    while (!stopToken.stop_requested()) {
        // events[0] = virtual channel manager, events[1] = stopEvent (signalled
        // for teardown), the rest = peer transport handles.
        std::array<HANDLE, 33> events{channelEvent, d->stopEvent};
        auto handleCount = d->peer->GetEventHandles(d->peer, events.data() + 2, 31);
        if (handleCount <= 0) {
            qCWarning(KRDP) << "RDP event loop exiting: unable to get transport event handles";
            break;
        }
        // Wait for something to happen on the connection.
        const DWORD waitStatus = WaitForMultipleObjects(2 + handleCount, events.data(), FALSE, INFINITE);
        if (waitStatus == WAIT_FAILED) {
            qCWarning(KRDP) << "RDP event loop exiting: WaitForMultipleObjects failed";
            break;
        }

        // Bail out before touching the peer transport if we were asked to stop,
        // so teardown stays race-free.
        if (stopToken.stop_requested()) {
            qCInfo(KRDP) << "RDP event loop exiting: stop requested";
            break;
        }

        // Read data from the socket and have FreeRDP process it.
        if (d->peer->CheckFileDescriptor(d->peer) != TRUE) {
            qCInfo(KRDP) << "RDP event loop exiting: peer CheckFileDescriptor returned FALSE";
            break;
        }

        const bool cliprdrJoined = WTSVirtualChannelManagerIsChannelJoined(context->virtualChannelManager, CLIPRDR_SVC_CHANNEL_NAME);
        const bool drdynvcJoined = WTSVirtualChannelManagerIsChannelJoined(context->virtualChannelManager, DRDYNVC_SVC_CHANNEL_NAME);
        const BYTE drdynvcState = WTSVirtualChannelManagerGetDrdynvcState(context->virtualChannelManager);

        if (d->peer->connected && state() == State::Activated && drdynvcJoined && drdynvcState == DRDYNVC_STATE_NONE) {
            if (WTSVirtualChannelManagerOpen(context->virtualChannelManager) != TRUE) {
                qCWarning(KRDP) << "RDP event loop exiting: unable to open Virtual Channel Manager for drdynvc";
                break;
            }
        }

        if (WTSVirtualChannelManagerCheckFileDescriptorEx(context->virtualChannelManager, FALSE) != TRUE) {
            qCWarning(KRDP) << "RDP event loop exiting: Virtual Channel Manager CheckFileDescriptorEx failed";
            break;
        }

        if (d->peer->connected && (state() == State::Activated || state() == State::Streaming) && cliprdrJoined && isAuthenticated()) {
            if (!d->clipboard->initialize()) {
                qCWarning(KRDP) << "RDP event loop exiting: clipboard initialization failed";
                break;
            }
        }

        const bool rdpsndSvcJoined = WTSVirtualChannelManagerIsChannelJoined(context->virtualChannelManager, RDPSND_CHANNEL_NAME);
        if (!audioInitAttempted && d->peer->connected && (state() == State::Activated || state() == State::Streaming) && isAuthenticated()) {
            const bool drdynvcReady = drdynvcJoined && drdynvcState == DRDYNVC_STATE_READY;
            if (drdynvcReady || rdpsndSvcJoined) {
                audioInitAttempted = true;
                bool audioOk = false;
                if (drdynvcReady) {
                    audioOk = d->audioStream->initialize(true);
                }
                if (!audioOk && rdpsndSvcJoined) {
                    audioOk = d->audioStream->initialize(false);
                }
                if (!audioOk) {
                    qCWarning(KRDP) << "RDPSND audio redirection could not be started (continuing without audio)";
                }
            }
        }

        if (!audioInputInitAttempted && d->peer->connected && (state() == State::Activated || state() == State::Streaming) && isAuthenticated() && drdynvcJoined
            && drdynvcState == DRDYNVC_STATE_READY) {
            audioInputInitAttempted = true;
            if (!d->audioInputStream->initialize()) {
                qCInfo(KRDP) << "AUDIN microphone redirection not active (continuing without microphone)";
            }
        }

        if (d->peer->connected && state() == State::Activated && drdynvcJoined && drdynvcState == DRDYNVC_STATE_READY) {
            if (!d->displayControl->initialize()) {
                qCWarning(KRDP) << "RDP event loop exiting: display control initialization failed";
                break;
            }
            if (!d->videoStream->initialize()) {
                qCWarning(KRDP) << "RDP event loop exiting: video stream initialization failed";
                break;
            }
            d->videoStream->setEnabled(true);
        }

        if (drdynvcJoined != lastDrdynvcJoined || drdynvcState != lastDrdynvcState) {
            qCInfo(KRDP) << "Dynamic virtual channel state transition: drdynvcJoined=" << drdynvcJoined << "drdynvcState=" << int(drdynvcState)
                         << "cliprdrJoined=" << cliprdrJoined;
            lastDrdynvcJoined = drdynvcJoined;
            lastDrdynvcState = drdynvcState;
        }

        if (d->peer->connected && state() == State::Activated && drdynvcJoined) {
            if (drdynvcState == DRDYNVC_STATE_READY) {
                if (!d->videoStream->openChannel()) {
                    qCWarning(KRDP) << "Unable to open RDPGFX channel";
                } else {
                    qCInfo(KRDP) << "RDPGFX channel opened; entering State::Streaming (authState=" << int(authState()) << ")";
                    setState(State::Streaming);
                    if (d->authState.load(std::memory_order_acquire) == AuthState::PendingInBandGreeter) {
                        QMetaObject::invokeMethod(this, &RdpConnection::startInBandGreeter, Qt::QueuedConnection);
                    }
                }
            }
        }

        d->networkDetection->update();
    }

    qCDebug(KRDP) << "Closing session";

    // Close the peer here, on the thread that owns it. Every other close path
    // just asks this thread to stop, so once a run thread exists this is the
    // only place the transport is driven - keeping teardown single-threaded.
    if (d->peer) {
        d->peer->Close(d->peer);
    }

    onClose();
}

bool RdpConnection::onCapabilities()
{
    auto settings = d->peer->context->settings;
    if (!freerdp_settings_get_bool(settings, FreeRDP_SupportGraphicsPipeline)) {
        qCWarning(KRDP) << "Client does not support graphics pipeline which is required";
        return false;
    }

    auto colorDepth = freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth);
    if (colorDepth != 32) {
        qCDebug(KRDP) << "Correcting invalid color depth from client:" << colorDepth;
        freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32);
    }

    if (freerdp_settings_get_uint32(settings, FreeRDP_PointerCacheSize) <= 0) {
        qCWarning(KRDP) << "Client doesn't support pointer caching, aborting";
        return false;
    }

    qCInfo(KRDP) << "Peer capabilities negotiated: desktop=" << freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth) << "x"
                 << freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight)
                 << "fastPathInput=" << freerdp_settings_get_bool(settings, FreeRDP_FastPathInput)
                 << "unicodeInput=" << freerdp_settings_get_bool(settings, FreeRDP_UnicodeInput)
                 << "pointerCache=" << freerdp_settings_get_uint32(settings, FreeRDP_PointerCacheSize);

    return true;
}

static std::optional<quint8> qualitySeedForConnectionType(uint32_t connectionType)
{
    switch (connectionType) {
    case CONNECTION_TYPE_MODEM:
        return 30;
    case CONNECTION_TYPE_BROADBAND_LOW:
        return 50;
    case CONNECTION_TYPE_SATELLITE:
        return 45;
    case CONNECTION_TYPE_WAN:
        return 70;
    case CONNECTION_TYPE_BROADBAND_HIGH:
        return 80;
    case CONNECTION_TYPE_LAN:
        return 95;
    default:
        return std::nullopt;
    }
}

bool RdpConnection::onActivate()
{
    d->activateCount++;
    qCInfo(KRDP) << "Peer activated (count=" << d->activateCount << ", authState=" << int(authState()) << ")";
    setState(State::Activated);

    if (!d->qualitySeeded) {
        d->qualitySeeded = true;
        const uint32_t connectionType = freerdp_settings_get_uint32(d->peer->context->settings, FreeRDP_ConnectionType);
        if (const auto seed = qualitySeedForConnectionType(connectionType)) {
            QMetaObject::invokeMethod(
                d->videoStream.get(),
                [videoStream = d->videoStream.get(), seed = *seed]() {
                    videoStream->seedQuality(seed);
                },
                Qt::QueuedConnection);
        }
    }

    return true;
}

bool RdpConnection::onPostConnect()
{
    qCInfo(KRDP) << "New client connected:" << d->peer->hostname << freerdp_peer_os_major_type_string(d->peer) << freerdp_peer_os_minor_type_string(d->peer);

    rdpSettings *settings = d->peer->context->settings;
    const QString username = QString::fromUtf8(freerdp_settings_get_string(settings, FreeRDP_Username)).section(QLatin1Char('\\'), -1);

    if (!username.isEmpty() && isDisallowedLoginUser(username)) {
        qCWarning(KRDP) << "Rejecting disallowed RDP login user:" << username;
        return false;
    }

    const bool requirePostConnectAuth = d->server->usePAMAuthentication() || d->transportInfo.vmConnectMode;

    if (requirePostConnectAuth) {
        if (!freerdp_settings_set_bool(settings, FreeRDP_AutoLogonEnabled, true)) {
            return false;
        }

        const QString password = QString::fromUtf8(freerdp_settings_get_string(settings, FreeRDP_Password));
        if (password.isEmpty()) {
            if (d->transportInfo.vmConnectMode && d->transportInfo.inBandGreeterEnabled) {
                qCInfo(KRDP) << "Hyper-V VMConnect peer sent no password in TS_INFO_PACKET; entering isolated in-band login greeter";
                setAuthState(AuthState::PendingInBandGreeter);
                return true;
            }
            qCWarning(KRDP) << "Rejecting unauthenticated RDP connection (missing password in TS_INFO_PACKET)"
                            << (d->transportInfo.vmConnectMode ? "[Hyper-V VMConnect mode]" : "");
            return false;
        }

        if (username.isEmpty()) {
            qCWarning(KRDP) << "Rejecting unauthenticated RDP connection (missing username in TS_INFO_PACKET)";
            return false;
        }

        if (verifyGuestCredentials(username, password)) {
            {
                std::lock_guard lock(d->authUserMutex);
                d->authenticatedUser = username.trimmed();
            }
            setAuthState(AuthState::Authenticated);
            return true;
        }

        qCWarning(KRDP) << "Authentication failed for user" << username;
        return false;
    } else {
        // In the standard TCP NLA case, the user has been authorised against the SAM database
        // (from which disallowed/root users are excluded).
        {
            std::lock_guard lock(d->authUserMutex);
            d->authenticatedUser = username.trimmed();
        }
        setAuthState(AuthState::Authenticated);
        return true;
    }
}

bool RdpConnection::onClose()
{
    qCInfo(KRDP) << "Closing RDP connection (authState=" << int(authState()) << ")";
    QMetaObject::invokeMethod(d->inBandGreeter.get(), &InBandGreeter::stop, Qt::QueuedConnection);
    d->displayControl->close();
    d->clipboard->close();
    d->audioInputStream->close();
    d->audioStream->close();
    d->videoStream->close();
    {
        std::lock_guard lock(d->authUserMutex);
        d->authenticatedUser.clear();
    }
    d->authenticatedViaPam.store(false, std::memory_order_release);
    setState(State::Closed);
    return true;
}

bool RdpConnection::onSuppressOutput(uint8_t allow)
{
    qCInfo(KRDP) << "Client SuppressOutput PDU:" << (allow ? "allow" : "suppress");
    if (allow) {
        d->videoStream->setEnabled(true);
    } else {
        d->videoStream->setEnabled(false);
    }

    return true;
}

freerdp_peer *RdpConnection::rdpPeer() const
{
    return d->peer;
}

rdpContext *RdpConnection::rdpPeerContext() const
{
    return d->peer->context;
}
}

#include "moc_RdpConnection.cpp"
