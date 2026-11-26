// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <csignal>
#include <filesystem>

#include <QApplication>
#include <QCommandLineParser>
#include <QRegularExpression>

#include <KAboutData>
#include <KCrash>
#include <KSharedConfig>
#include <KSignalHandler>

#include <qt6keychain/keychain.h>

#include "Server.h"
#include "SessionController.h"
#include "krdp_version.h"
#include "krdpserversettings.h"

using namespace Qt::StringLiterals;

static std::optional<KRdp::Server::Transport> parseTransport(QAnyStringView value)
{
    if (value == u"tcp"_s) {
        return KRdp::Server::Transport::Tcp;
    }
    if (value == u"vsock"_s) {
        return KRdp::Server::Transport::Vsock;
    }
    return std::nullopt;
}

static std::optional<SessionController::OperationMode> parseOperationMode(QAnyStringView value)
{
    if (value == u"RemoteAccess"_s) {
        return SessionController::OperationMode::RemoteAccess;
    }
    if (value == u"SharedAccess"_s) {
        return SessionController::OperationMode::SharedAccess;
    }
    if (value == u"AdditionalDisplay"_s) {
        return SessionController::OperationMode::AdditionalDisplay;
    }

    return std::nullopt;
}

int main(int argc, char **argv)
{
    QApplication application{argc, argv};
    application.setApplicationName(u"krdp-server"_s);
    application.setApplicationDisplayName(u"KRDP Server"_s);

    KAboutData about(u"krdp-server"_s, u"KRDP Server"_s, QStringLiteral(KRdp_VERSION_STRING));
    about.setDesktopFileName(u"org.kde.krdpserver"_s);
    KAboutData::setApplicationData(about);

    KCrash::initialize();

    QCommandLineParser parser;
    parser.setApplicationDescription(
        u"An RDP server that exposes the current desktop session over the RDP protocol.\nNote that a valid TLS certificate and key is needed. If not provided, a temporary certificate will be generated."_s);
    parser.addOptions({
        {{u"u"_s, u"username"_s}, u"The username to use for login"_s, u"username"_s},
        {{u"p"_s, u"password"_s}, u"The password to use for login. Requires username to be passed as well."_s, u"password"_s},
        {u"address"_s, u"The address to listen on for connections. Defaults to 0.0.0.0"_s, u"address"_s},
        {u"port"_s, u"The port to use for connections. Defaults to 3389."_s, u"port"_s, u"3389"_s},
        {u"transport"_s, u"The transport to listen on: tcp (default) or vsock (Hyper-V Enhanced Session AF_VSOCK)."_s, u"transport"_s, u"tcp"_s},
        {u"vmconnect"_s, u"Enable Hyper-V VMConnect mode (only valid with --transport vsock; enabled by default for vsock)."_s},
        {u"no-vmconnect"_s, u"Disable Hyper-V VMConnect mode on --transport vsock and require full TLS/NLA."_s},
        {u"in-band-greeter"_s,
         u"Enable isolated in-band login greeter for Hyper-V VMConnect clients that omit a password in TS_INFO_PACKET (default: on for vsock vmconnect)."_s},
        {u"no-in-band-greeter"_s, u"Disable the in-band login greeter and reject connections that omit a password in TS_INFO_PACKET."_s},
        {u"vsock-cid"_s, u"The AF_VSOCK CID to bind to when using --transport vsock (numeric CID or 'any', default: any)."_s, u"cid"_s, u"any"_s},
        {u"vsock-peer-cid"_s, u"The only AF_VSOCK peer CID permitted to connect (default: 2 / VMADDR_CID_HOST)."_s, u"cid"_s, u"2"_s},
        {u"pam"_s, u"Enable PAM authentication for the current non-root user."_s},
        {u"certificate"_s, u"The TLS certificate file to use."_s, u"certificate"_s, u"server.crt"_s},
        {u"certificate-key"_s, u"The TLS certificate key to use."_s, u"certificate-key"_s, u"server.key"_s},
        {u"monitor"_s, u"The index of the monitor to use when streaming."_s, u"monitor"_s, u"-1"_s},
        {u"virtual-monitor"_s,
         u"Creates a new virtual output to connect to (WIDTHxHEIGHT@SCALE, e.g. 1920x1080@1). Incompatible with --monitor."_s,
         u"data"_s,
         u"1920x1080@1"_s},
        {u"mode"_s, u"The operation mode to use: RemoteAccess, SharedAccess, or AdditionalDisplay."_s, u"mode"_s},
        {u"quality"_s,
         u"Encoding quality of the stream, from 0 (lowest) to 100 (highest). With adaptive quality (the default) this is the upper bound; with --static-quality it is the fixed quality."_s,
         u"quality"_s},
        {u"adaptive-quality"_s,
         u"Adjust the encoding quality at runtime based on the client's network conditions, up to --quality. On by default; only matters if disabled in the configuration."_s},
        {u"static-quality"_s, u"Pin the encoding quality at --quality instead of adapting it to the client's network conditions."_s},
#ifdef WITH_PLASMA_SESSION
        {u"plasma"_s, u"Use Plasma protocols instead of XDP"_s},
#endif
    });
    about.setupCommandLine(&parser);
    parser.process(application);
    about.processCommandLine(&parser);

    KSignalHandler::self()->watchSignal(SIGINT);
    KSignalHandler::self()->watchSignal(SIGTERM);
    QObject::connect(KSignalHandler::self(), &KSignalHandler::signalReceived, &application, [](int) {
        QCoreApplication::exit(0);
    });

    auto config = ServerConfig::self();

    auto parserValueWithDefault = [&parser](QAnyStringView option, auto defaultValue) {
        auto optionString = option.toString();
        if (parser.isSet(optionString)) {
            return QVariant(parser.value(optionString)).value<decltype(defaultValue)>();
        } else {
            return defaultValue;
        }
    };

    const auto transport = parseTransport(parser.value(u"transport"_s).toLower());
    if (!transport) {
        qWarning() << "failed to parse transport" << parser.value(u"transport"_s) << ". Expected tcp or vsock";
        return 1;
    }

    if (parser.isSet(u"vmconnect"_s) && parser.isSet(u"no-vmconnect"_s)) {
        qWarning() << "--vmconnect and --no-vmconnect cannot be combined";
        return 1;
    }

    if (parser.isSet(u"in-band-greeter"_s) && parser.isSet(u"no-in-band-greeter"_s)) {
        qWarning() << "--in-band-greeter and --no-in-band-greeter cannot be combined";
        return 1;
    }

    const bool hyperVMode = (*transport == KRdp::Server::Transport::Vsock) ? !parser.isSet(u"no-vmconnect"_s) : parser.isSet(u"vmconnect"_s);
    if (hyperVMode && *transport != KRdp::Server::Transport::Vsock) {
        qWarning() << "--vmconnect is strictly restricted to --transport vsock and cannot be used with TCP";
        return 1;
    }

    const bool inBandGreeter = hyperVMode ? !parser.isSet(u"no-in-band-greeter"_s) : parser.isSet(u"in-band-greeter"_s);
    if (inBandGreeter && !hyperVMode) {
        qWarning() << "--in-band-greeter is strictly restricted to --transport vsock with --vmconnect";
        return 1;
    }

    QHostAddress address = QHostAddress::Any;
    if (parser.isSet(u"address"_s)) {
        address = QHostAddress(parser.value(u"address"_s));
    }
    auto port = parserValueWithDefault(u"port", config->listenPort());
    auto certificate = std::filesystem::path(parserValueWithDefault(u"certificate", config->certificate()).toStdString());
    auto certificateKey = std::filesystem::path(parserValueWithDefault(u"certificate-key", config->certificateKey()).toStdString());

    KRdp::Server server(nullptr);

    server.setTransport(*transport);
    server.setHyperVMode(hyperVMode);
    server.setInBandGreeterEnabled(inBandGreeter);
    if (*transport == KRdp::Server::Transport::Vsock) {
        const QString bindCidStr = parser.value(u"vsock-cid"_s).trimmed().toLower();
        if (bindCidStr != u"any"_s) {
            bool ok = false;
            const quint32 cid = bindCidStr.toUInt(&ok);
            if (!ok) {
                qWarning() << "failed to parse --vsock-cid" << bindCidStr << ". Expected numeric CID or 'any'";
                return 1;
            }
            server.setVsockBindCid(cid);
        }

        const QString peerCidStr = parser.value(u"vsock-peer-cid"_s).trimmed().toLower();
        bool peerOk = false;
        const quint32 peerCid = peerCidStr.toUInt(&peerOk);
        if (!peerOk || peerCid == 0xFFFFFFFFU) {
            qWarning() << "invalid --vsock-peer-cid" << peerCidStr << ". Expected an explicit numeric CID (default: 2 / VMADDR_CID_HOST)";
            return 1;
        }
        server.setAllowedVsockPeerCid(peerCid);
    }

    server.setAddress(address);
    server.setPort(port);

    server.setTlsCertificate(certificate);
    server.setTlsCertificateKey(certificateKey);

    // Use parsed username/pw if set
    if (parser.isSet(u"username"_s)) {
        KRdp::User user;
        user.name = parser.value(u"username"_s);
        user.password = parser.value(u"password"_s);
        server.addUser(user);
        if (parser.isSet(u"pam"_s)) {
            server.setUsePAMAuthentication(true);
        }
    }
    // Otherwise use KCM username list
    else {
        server.setUsePAMAuthentication(config->systemUserEnabled() || parser.isSet(u"pam"_s));

        const auto users = config->users();
        for (const auto &userName : users) {
            const auto readJob = new QKeychain::ReadPasswordJob(QLatin1StringView("KRDP"));
            readJob->setKey(QLatin1StringView(userName.toLatin1()));
            QObject::connect(readJob, &QKeychain::ReadPasswordJob::finished, &server, [userName, readJob, &server]() {
                KRdp::User user;
                if (readJob->error() != QKeychain::Error::NoError) {
                    qWarning() << "requestPassword: Failed to read password of " << userName << " because of error: " << readJob->error();
                    return;
                }
                user.name = userName;
                user.password = readJob->textData();
                server.addUser(user);
            });
            readJob->start();
        }
        if (users.isEmpty() && !server.usePAMAuthentication()) {
            qWarning() << "No users configured for login. Either pass a username/password or configure users using kcm_krdp.";
            return -1;
        }
    }

    SessionController controller(&server, parser.isSet(u"plasma"_s) ? SessionController::SessionType::Plasma : SessionController::SessionType::Portal);
    if (parser.isSet(u"virtual-monitor"_s)) {
        const QString vmData = parser.value(u"virtual-monitor"_s);
        const QRegularExpression rx(uR"((\d+)x(\d+)@([\d.]+))"_s);
        const auto match = rx.match(vmData);
        if (!match.hasMatch()) {
            qWarning() << "failed to parse" << vmData << ".  Should be WIDTHxHEIGHT@SCALE";
            return 1;
        }
        controller.setVirtualMonitor({vmData, {match.capturedView(1).toInt(), match.capturedView(2).toInt()}, match.capturedView(3).toDouble()});
    } else {
        controller.setMonitorIndex(parser.isSet(u"monitor"_s) ? std::optional(parser.value(u"monitor"_s).toInt()) : std::nullopt);
    }
    const bool isVsock = (*transport == KRdp::Server::Transport::Vsock);
    const int defaultQuality = isVsock ? 95 : config->quality();
    const bool defaultAdaptiveQuality = isVsock ? false : config->adaptiveQuality();
    controller.setQuality(parserValueWithDefault(u"quality", defaultQuality));
    controller.setAdaptiveQuality((parser.isSet(u"adaptive-quality"_s) || defaultAdaptiveQuality) && !parser.isSet(u"static-quality"_s));
    if (parser.isSet(u"mode"_s)) {
        const auto mode = parseOperationMode(parser.value(u"mode"_s));
        if (!mode) {
            qWarning() << "failed to parse operation mode" << parser.value(u"mode"_s) << ". Expected RemoteAccess, SharedAccess, or AdditionalDisplay";
            return 1;
        }
        controller.setOperationMode(*mode);
    } else {
        controller.setOperationMode(config->exclusiveMode() ? SessionController::OperationMode::RemoteAccess : SessionController::OperationMode::SharedAccess);
    }

    if (!server.start()) {
        return -1;
    }

    return application.exec();
}
