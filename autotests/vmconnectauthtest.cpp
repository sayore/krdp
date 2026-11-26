// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QByteArray>
#include <QDataStream>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QKeyEvent>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QtEndian>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <freerdp/codec/zgfx.h>

#include "AudioInputStream.h"
#include "AudioStream.h"
#include "Clipboard.h"
#include "InBandGreeter.h"
#include "RdpConnection.h"
#include "Server.h"

namespace
{

void appendU8(QByteArray &buf, uint8_t v)
{
    buf.append(static_cast<char>(v));
}

void appendU16LE(QByteArray &buf, uint16_t v)
{
    appendU8(buf, static_cast<uint8_t>(v & 0xFF));
    appendU8(buf, static_cast<uint8_t>((v >> 8) & 0xFF));
}

void appendU16BE(QByteArray &buf, uint16_t v)
{
    appendU8(buf, static_cast<uint8_t>((v >> 8) & 0xFF));
    appendU8(buf, static_cast<uint8_t>(v & 0xFF));
}

void appendU32LE(QByteArray &buf, uint32_t v)
{
    appendU8(buf, static_cast<uint8_t>(v & 0xFF));
    appendU8(buf, static_cast<uint8_t>((v >> 8) & 0xFF));
    appendU8(buf, static_cast<uint8_t>((v >> 16) & 0xFF));
    appendU8(buf, static_cast<uint8_t>((v >> 24) & 0xFF));
}

void appendBerLen(QByteArray &buf, size_t len)
{
    if (len < 0x80) {
        appendU8(buf, static_cast<uint8_t>(len));
    } else if (len < 0x100) {
        appendU8(buf, 0x81);
        appendU8(buf, static_cast<uint8_t>(len));
    } else {
        appendU8(buf, 0x82);
        appendU8(buf, static_cast<uint8_t>((len >> 8) & 0xFF));
        appendU8(buf, static_cast<uint8_t>(len & 0xFF));
    }
}

void appendBerInt(QByteArray &buf, uint32_t val)
{
    appendU8(buf, 0x02); // INTEGER
    if (val < 0x80) {
        appendU8(buf, 1);
        appendU8(buf, static_cast<uint8_t>(val));
    } else if (val < 0x8000) {
        appendU8(buf, 2);
        appendU16BE(buf, static_cast<uint16_t>(val));
    } else {
        appendU8(buf, 3);
        appendU8(buf, static_cast<uint8_t>((val >> 16) & 0xFF));
        appendU8(buf, static_cast<uint8_t>((val >> 8) & 0xFF));
        appendU8(buf, static_cast<uint8_t>(val & 0xFF));
    }
}

void appendDomainParams(QByteArray &buf, uint32_t maxChannels, uint32_t maxUsers, uint32_t maxTokens, uint32_t maxPdu)
{
    QByteArray inner;
    appendBerInt(inner, maxChannels);
    appendBerInt(inner, maxUsers);
    appendBerInt(inner, maxTokens);
    appendBerInt(inner, 1); // numPriorities
    appendBerInt(inner, 0); // minThroughput
    appendBerInt(inner, 1); // maxHeight
    appendBerInt(inner, maxPdu);
    appendBerInt(inner, 2); // protocolVersion

    appendU8(buf, 0x30); // SEQUENCE
    appendBerLen(buf, static_cast<size_t>(inner.size()));
    buf.append(inner);
}

QByteArray wrapTpktX224Data(const QByteArray &payload)
{
    const uint16_t totalLen = static_cast<uint16_t>(4 + 3 + payload.size());
    QByteArray pkt;
    pkt.reserve(totalLen);
    appendU8(pkt, 0x03); // TPKT v3
    appendU8(pkt, 0x00);
    appendU16BE(pkt, totalLen);
    appendU8(pkt, 0x02); // X.224 LI=2
    appendU8(pkt, 0xF0); // X.224 DT
    appendU8(pkt, 0x80); // EOT
    pkt.append(payload);
    return pkt;
}

QByteArray wrapMcsSendDataRequest(uint16_t userId, uint16_t channelId, const QByteArray &data)
{
    QByteArray mcs;
    appendU8(mcs, 0x64); // MCS SendDataRequest (domainMCSPDU=25 -> 25<<2 = 0x64)
    appendU16BE(mcs, static_cast<uint16_t>(userId - 1001));
    appendU16BE(mcs, channelId);
    appendU8(mcs, 0x70); // dataPriority=high, segmentation=begin|end
    if (data.size() >= 0x80) {
        appendU16BE(mcs, static_cast<uint16_t>(0x8000 | data.size()));
    } else {
        appendU8(mcs, static_cast<uint8_t>(data.size()));
    }
    mcs.append(data);
    return wrapTpktX224Data(mcs);
}

QByteArray toUtf16LE(const QString &str)
{
    QByteArray out;
    out.reserve(str.size() * 2);
    for (const QChar ch : str) {
        appendU16LE(out, ch.unicode());
    }
    return out;
}

bool sendAll(int fd, const QByteArray &data)
{
    ssize_t sent = 0;
    while (sent < data.size()) {
        const ssize_t n = ::send(fd, data.constData() + sent, static_cast<size_t>(data.size() - sent), MSG_NOSIGNAL);
        if (n <= 0) {
            return false;
        }
        sent += n;
    }
    return true;
}

bool recvExact(int fd, char *dst, size_t len, int timeoutMs = 3000)
{
    size_t got = 0;
    while (got < len) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, timeoutMs);
        if (pr <= 0) {
            return false;
        }
        const ssize_t n = ::recv(fd, dst + got, len - got, 0);
        if (n <= 0) {
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

QByteArray recvTpkt(int fd, int timeoutMs = 3000)
{
    char hdr[4] = {};
    if (!recvExact(fd, hdr, 4, timeoutMs)) {
        return {};
    }
    if (static_cast<uint8_t>(hdr[0]) != 0x03) {
        return {};
    }
    const uint16_t totalLen = static_cast<uint16_t>((static_cast<uint8_t>(hdr[2]) << 8) | static_cast<uint8_t>(hdr[3]));
    if (totalLen < 4) {
        return {};
    }
    QByteArray pkt(totalLen, Qt::Uninitialized);
    std::memcpy(pkt.data(), hdr, 4);
    if (totalLen > 4 && !recvExact(fd, pkt.data() + 4, totalLen - 4, timeoutMs)) {
        return {};
    }
    return pkt;
}

/**
 * Build a spec-compliant MS-RDPBCGR MCS Connect Initial PDU with GCC Conference Create Request
 * (CS_CORE, CS_SECURITY, CS_NET with cliprdr + drdynvc) matching Hyper-V VMConnect.
 */
QByteArray buildMcsConnectInitial()
{
    // CS_CORE (0xC001) - MS-RDPBCGR 2.2.1.3.2
    QByteArray csCoreBody;
    appendU32LE(csCoreBody, 0x00080004); // RDP 5.0+ version
    appendU16LE(csCoreBody, 1280); // desktopWidth
    appendU16LE(csCoreBody, 720); // desktopHeight
    appendU16LE(csCoreBody, 0xCA01); // colorDepth
    appendU16LE(csCoreBody, 0xAA03); // SASSequence
    appendU32LE(csCoreBody, 0x00000409); // keyboardLayout
    appendU32LE(csCoreBody, 2600); // clientBuild
    QByteArray hostUtf16 = toUtf16LE(QStringLiteral("HYPERV-HOST"));
    hostUtf16.resize(32, '\0');
    csCoreBody.append(hostUtf16);
    appendU32LE(csCoreBody, 4); // keyboardType
    appendU32LE(csCoreBody, 0); // keyboardSubType
    appendU32LE(csCoreBody, 12); // keyboardFunctionKey
    csCoreBody.append(QByteArray(64, '\0')); // imeFileName
    appendU16LE(csCoreBody, 0xCA01); // postBeta2ColorDepth
    appendU16LE(csCoreBody, 1); // clientProductId
    appendU32LE(csCoreBody, 0); // serialNumber
    appendU16LE(csCoreBody, 24); // highColorDepth
    appendU16LE(csCoreBody, 0x000F); // supportedColorDepths
    // RNS_UD_CS_SUPPORT_ERRINFO_PDU (0x0001) | RNS_UD_CS_WANT_32BPP_SESSION (0x0002) |
    // RNS_UD_CS_VALID_CONNECTION_TYPE (0x0020) | RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU (0x0040) |
    // RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL (0x0100)
    appendU16LE(csCoreBody, 0x0163);
    csCoreBody.append(QByteArray(64, '\0')); // clientDigProductId
    appendU8(csCoreBody, 0x06); // connectionType = LAN
    appendU8(csCoreBody, 0x00); // pad1octet
    appendU32LE(csCoreBody, 0x00000001); // serverSelectedProtocol = PROTOCOL_SSL

    QByteArray csCore;
    appendU16LE(csCore, 0xC001);
    appendU16LE(csCore, static_cast<uint16_t>(4 + csCoreBody.size()));
    csCore.append(csCoreBody);

    // CS_SECURITY (0xC002)
    QByteArray csSec;
    appendU16LE(csSec, 0xC002);
    appendU16LE(csSec, 12);
    appendU32LE(csSec, 0); // encryptionMethods
    appendU32LE(csSec, 0); // extEncryptionMethods

    // CS_NET (0xC003): cliprdr + drdynvc
    QByteArray csNet;
    appendU16LE(csNet, 0xC003);
    appendU16LE(csNet, static_cast<uint16_t>(8 + 2 * 12));
    appendU32LE(csNet, 2); // channelCount
    auto addChannel = [&](const char *name, uint32_t opts) {
        QByteArray n(8, '\0');
        std::memcpy(n.data(), name, std::min<size_t>(8, std::strlen(name)));
        csNet.append(n);
        appendU32LE(csNet, opts);
    };
    addChannel("cliprdr", 0xC0A00000);
    addChannel("drdynvc", 0xC0800000);

    QByteArray gccUserData;
    gccUserData.append(csCore);
    gccUserData.append(csSec);
    gccUserData.append(csNet);

    // T.124 GCC Conference Create Request header (standard MS-RDPBCGR 2.2.1.3)
    QByteArray gcc;
    // Per-encoded ConnectData + ConferenceCreateRequest
    gcc.append(QByteArray::fromHex("000500147c000181"));
    const uint16_t gccRem = static_cast<uint16_t>(14 + gccUserData.size());
    // Replace 0x81xx two-byte PER length
    gcc.chop(1);
    appendU16BE(gcc, static_cast<uint16_t>(0x8000 | gccRem));
    gcc.append(QByteArray::fromHex("000800100001c00044756361")); // "Duca" H.221 key
    appendU16BE(gcc, static_cast<uint16_t>(0x8000 | gccUserData.size()));
    gcc.append(gccUserData);

    // MCS Connect Initial (BER APPLICATION 101 = 0x7F 0x65)
    QByteArray body;
    // callingDomainSelector = 0x01
    body.append(QByteArray::fromHex("040101"));
    // calledDomainSelector = 0x01
    body.append(QByteArray::fromHex("040101"));
    // upwardFlag = TRUE
    body.append(QByteArray::fromHex("0101ff"));
    // targetParameters, minimumParameters, maximumParameters
    appendDomainParams(body, 34, 2, 0, 65535);
    appendDomainParams(body, 1, 1, 1, 1056);
    appendDomainParams(body, 65535, 64535, 65535, 65535);
    // userData OCTET STRING
    appendU8(body, 0x04);
    appendBerLen(body, static_cast<size_t>(gcc.size()));
    body.append(gcc);

    QByteArray mcsCi;
    appendU8(mcsCi, 0x7F);
    appendU8(mcsCi, 0x65);
    appendBerLen(mcsCi, static_cast<size_t>(body.size()));
    mcsCi.append(body);
    return wrapTpktX224Data(mcsCi);
}

QByteArray buildClientInfoPdu(uint16_t userId, const QString &username, const QString &password)
{
    const QByteArray domU16 = toUtf16LE(QString());
    const QByteArray usrU16 = toUtf16LE(username);
    const QByteArray pwdU16 = toUtf16LE(password);
    const QByteArray shellU16 = toUtf16LE(QString());
    const QByteArray dirU16 = toUtf16LE(QString());
    const QByteArray addrU16 = toUtf16LE(QStringLiteral("127.0.0.1"));
    const QByteArray cdirU16 = toUtf16LE(QString());

    QByteArray info;
    // TS_SECURITY_HEADER (SEC_INFO_PKT = 0x0040)
    appendU16LE(info, 0x0040);
    appendU16LE(info, 0x0000);

    // TS_INFO_PACKET
    appendU32LE(info, 0); // CodePage
    uint32_t flags = 0x00000001u | 0x00000010u | 0x00000033u; // INFO_MOUSE | INFO_UNICODE | INFO_DISABLECTRLALTDEL | INFO_MAXIMIZESHELL
    if (!password.isEmpty()) {
        flags |= 0x00000008u; // INFO_AUTOLOGON
    }
    appendU32LE(info, flags);
    appendU16LE(info, static_cast<uint16_t>(domU16.size()));
    appendU16LE(info, static_cast<uint16_t>(usrU16.size()));
    appendU16LE(info, static_cast<uint16_t>(pwdU16.size()));
    appendU16LE(info, static_cast<uint16_t>(shellU16.size()));
    appendU16LE(info, static_cast<uint16_t>(dirU16.size()));

    info.append(domU16);
    appendU16LE(info, 0);
    info.append(usrU16);
    appendU16LE(info, 0);
    info.append(pwdU16);
    appendU16LE(info, 0);
    info.append(shellU16);
    appendU16LE(info, 0);
    info.append(dirU16);
    appendU16LE(info, 0);

    // TS_EXTENDED_INFO_PACKET (minimal valid fields)
    appendU16LE(info, 0x0002); // ADDRESS_FAMILY_INET
    appendU16LE(info, static_cast<uint16_t>(addrU16.size() + 2));
    info.append(addrU16);
    appendU16LE(info, 0);
    appendU16LE(info, static_cast<uint16_t>(cdirU16.size() + 2));
    info.append(cdirU16);
    appendU16LE(info, 0);

    return wrapMcsSendDataRequest(userId, 1003, info);
}

QByteArray buildShareControlPdu(uint16_t pduType, uint16_t pduSource, const QByteArray &payload)
{
    QByteArray pdu;
    appendU16LE(pdu, static_cast<uint16_t>(6 + payload.size()));
    appendU16LE(pdu, static_cast<uint16_t>(0x0010 | (pduType & 0x0F))); // version=1 | type
    appendU16LE(pdu, pduSource);
    pdu.append(payload);
    return pdu;
}

QByteArray buildShareDataPdu(uint32_t shareId, uint16_t userId, uint8_t pduType2, const QByteArray &data)
{
    QByteArray body;
    appendU32LE(body, shareId);
    appendU8(body, 0); // pad1
    appendU8(body, 1); // streamId = STREAM_LOW
    appendU16LE(body, static_cast<uint16_t>(data.size())); // uncompressedLength
    appendU8(body, pduType2);
    appendU8(body, 0); // compressedType
    appendU16LE(body, 0); // compressedLength
    body.append(data);
    return wrapMcsSendDataRequest(userId, 1003, buildShareControlPdu(7 /* PDUTYPE_DATAPDU */, userId, body));
}

QByteArray buildConfirmActivePdu(uint32_t shareId, uint16_t userId)
{
    // Minimal capability sets required by FreeRDP server + KRdp::RdpConnection::onCapabilities()
    QByteArray caps;
    auto addCap = [&](uint16_t type, const QByteArray &data) {
        appendU16LE(caps, type);
        appendU16LE(caps, static_cast<uint16_t>(4 + data.size()));
        caps.append(data);
    };

    // CAPSTYPE_GENERAL (1) - 20 bytes payload
    QByteArray capGen(20, '\0');
    capGen[0] = 0x01; // OSMAJORTYPE_WINDOWS
    capGen[2] = 0x03; // OSMINORTYPE_WINDOWS_NT
    capGen[4] = 0x00;
    capGen[5] = 0x02; // protocolVersion = 0x0200
    addCap(0x0001, capGen);

    // CAPSTYPE_BITMAP (2) - 24 bytes payload
    QByteArray capBmp;
    appendU16LE(capBmp, 32); // preferredBitsPerPixel
    appendU16LE(capBmp, 1);
    appendU16LE(capBmp, 1);
    appendU16LE(capBmp, 1);
    appendU16LE(capBmp, 1280); // desktopWidth
    appendU16LE(capBmp, 720); // desktopHeight
    appendU16LE(capBmp, 0);
    appendU16LE(capBmp, 1); // desktopResizeFlag
    appendU16LE(capBmp, 1); // bitmapCompressionFlag
    appendU8(capBmp, 0); // highColorFlags
    appendU8(capBmp, 1); // drawingFlags
    appendU16LE(capBmp, 1); // multipleRectangleSupport
    appendU16LE(capBmp, 0); // pad2octetsB
    addCap(0x0002, capBmp);

    // CAPSTYPE_ORDER (3) - 84 bytes payload
    QByteArray capOrd(84, '\0');
    addCap(0x0003, capOrd);

    // CAPSTYPE_POINTER (8) - 6 bytes payload (colorPointerFlag=1, colorPointerCacheSize=25, pointerCacheSize=25)
    QByteArray capPtr;
    appendU16LE(capPtr, 1);
    appendU16LE(capPtr, 25);
    appendU16LE(capPtr, 25);
    addCap(0x0008, capPtr);

    // CAPSTYPE_INPUT (13) - 84 bytes payload
    QByteArray capInp(84, '\0');
    capInp[0] = 0x3D; // INPUT_FLAG_SCANCODES | MOUSEX | FASTPATH_INPUT | UNICODE | FASTPATH_INPUT2
    addCap(0x000D, capInp);

    const QByteArray sourceDesc = QByteArray("MSTSC\0", 6);
    QByteArray payload;
    appendU32LE(payload, shareId);
    appendU16LE(payload, 0x03EA); // originatorId
    appendU16LE(payload, static_cast<uint16_t>(sourceDesc.size()));
    appendU16LE(payload, static_cast<uint16_t>(4 + caps.size())); // lengthCombinedCapabilities
    payload.append(sourceDesc);
    appendU16LE(payload, 5); // numberCapabilities
    appendU16LE(payload, 0); // pad2Octets
    payload.append(caps);

    return wrapMcsSendDataRequest(userId, 1003, buildShareControlPdu(3 /* PDUTYPE_CONFIRMACTIVEPDU */, userId, payload));
}

struct HandshakeOutcome {
    bool negoSucceeded = false;
    uint8_t negoFlags = 0;
    uint32_t selectedProtocol = 0;
    bool mcsSucceeded = false;
    bool sentClientInfo = false;
    bool sentFinalize = false;
    uint16_t userId = 0;
    uint32_t shareId = 0;
};

/**
 * Executes the exact Hyper-V vmms.exe wire-protocol handshake over fd (WITHOUT TLS after RDP_NEG_RSP)
 * up through Finalization so FreeRDP triggers RdpConnection::onPostConnect() and onActivate().
 */
HandshakeOutcome runHyperVWireHandshake(int fd, const QString &username, const QString &password)
{
    HandshakeOutcome out;

    // 1. X.224 CR-TPDU with RDP_NEG_REQ = SSL|HYBRID|HYBRID_EX (0x0000000b)
    const QByteArray crTpdu = QByteArray::fromHex(
        "03000013"
        "0ee00000000000"
        "01000800"
        "0b000000");
    if (!sendAll(fd, crTpdu)) {
        return out;
    }

    // 2. X.224 CC-TPDU with RDP_NEG_RSP
    const QByteArray ccTpdu = recvTpkt(fd);
    if (ccTpdu.size() < 19 || static_cast<uint8_t>(ccTpdu[5]) != 0xD0 || static_cast<uint8_t>(ccTpdu[11]) != 0x02) {
        return out;
    }
    out.negoFlags = static_cast<uint8_t>(ccTpdu[12]);
    out.selectedProtocol = static_cast<uint32_t>(static_cast<uint8_t>(ccTpdu[15])) | (static_cast<uint32_t>(static_cast<uint8_t>(ccTpdu[16])) << 8)
        | (static_cast<uint32_t>(static_cast<uint8_t>(ccTpdu[17])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(ccTpdu[18])) << 24);
    out.negoSucceeded = true;

    // 3. NO TLS HANDSHAKE (Hyper-V vmms.exe behavior) -> Plaintext MCS Connect Initial
    if (!sendAll(fd, buildMcsConnectInitial())) {
        return out;
    }
    const QByteArray mcsResp = recvTpkt(fd);
    if (mcsResp.size() < 10 || static_cast<uint8_t>(mcsResp[7]) != 0x7F || static_cast<uint8_t>(mcsResp[8]) != 0x66) {
        return out;
    }

    // 4. MCS Erect Domain Request (0x04 0x01 0x00 0x01 0x00) + Attach User Request (0x28)
    if (!sendAll(fd, wrapTpktX224Data(QByteArray::fromHex("0401000100")))) {
        return out;
    }
    if (!sendAll(fd, wrapTpktX224Data(QByteArray::fromHex("28")))) {
        return out;
    }
    const QByteArray attachConfirm = recvTpkt(fd);
    if (attachConfirm.size() < 11 || (static_cast<uint8_t>(attachConfirm[7]) >> 2) != 11) {
        return out;
    }
    const uint16_t userId = static_cast<uint16_t>(1001 + ((static_cast<uint8_t>(attachConfirm[9]) << 8) | static_cast<uint8_t>(attachConfirm[10])));

    // 5. MCS Channel Join Requests (userId, 1003 global, 1004 cliprdr, 1005 drdynvc)
    const std::vector<uint16_t> channels = {userId, 1003, 1004, 1005};
    for (uint16_t ch : channels) {
        QByteArray cj;
        appendU8(cj, 0x38); // ChannelJoinRequest (14 << 2)
        appendU16BE(cj, static_cast<uint16_t>(userId - 1001));
        appendU16BE(cj, ch);
        if (!sendAll(fd, wrapTpktX224Data(cj))) {
            return out;
        }
        const QByteArray cjc = recvTpkt(fd);
        if (cjc.size() < 10) {
            return out;
        }
    }
    out.mcsSucceeded = true;

    // 6. Client Info PDU (TS_INFO_PACKET with test credentials)
    if (!sendAll(fd, buildClientInfoPdu(userId, username, password))) {
        return out;
    }
    out.sentClientInfo = true;

    // 7. Read server PDUs until Demand Active PDU (PDUTYPE_DEMANDACTIVEPDU == 1)
    uint32_t shareId = 0x000103EA;
    bool gotDemandActive = false;
    for (int i = 0; i < 8; ++i) {
        const QByteArray srvPkt = recvTpkt(fd, 2500);
        if (srvPkt.isEmpty()) {
            break;
        }
        // Scan MCS SendDataIndication payload for Share Control Header with PDUTYPE_DEMANDACTIVEPDU (0x0011)
        if (srvPkt.size() > 20 && static_cast<uint8_t>(srvPkt[7]) == 0x68) {
            // MCS SendDataIndication: 1 byte opcode + 2 initiator + 2 channel + 1 flags + 1/2 len
            int off = 7 + 1 + 2 + 2 + 1;
            if (static_cast<uint8_t>(srvPkt[off]) & 0x80) {
                off += 2;
            } else {
                off += 1;
            }
            if (off + 10 <= srvPkt.size()) {
                const uint16_t pduType = static_cast<uint16_t>(static_cast<uint8_t>(srvPkt[off + 2]) | (static_cast<uint8_t>(srvPkt[off + 3]) << 8));
                if ((pduType & 0x0F) == 1) {
                    shareId = static_cast<uint32_t>(static_cast<uint8_t>(srvPkt[off + 6])) | (static_cast<uint32_t>(static_cast<uint8_t>(srvPkt[off + 7])) << 8)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(srvPkt[off + 8])) << 16)
                        | (static_cast<uint32_t>(static_cast<uint8_t>(srvPkt[off + 9])) << 24);
                    gotDemandActive = true;
                    break;
                }
            }
        }
    }
    if (!gotDemandActive) {
        return out;
    }

    // 8. Send Confirm Active PDU + Client Finalization sequence (Sync, Cooperate, Request Control, Font List)
    if (!sendAll(fd, buildConfirmActivePdu(shareId, userId))) {
        return out;
    }

    // Synchronize PDU (pduType2 = 31)
    QByteArray syncData;
    appendU16LE(syncData, 1); // messageType = SYNCMSGTYPE_SYNC
    appendU16LE(syncData, 0x03EA); // targetUser
    if (!sendAll(fd, buildShareDataPdu(shareId, userId, 31, syncData))) {
        return out;
    }

    // Control Cooperate (pduType2 = 20, action = 4)
    QByteArray coopData;
    appendU16LE(coopData, 4);
    appendU16LE(coopData, 0);
    appendU32LE(coopData, 0);
    if (!sendAll(fd, buildShareDataPdu(shareId, userId, 20, coopData))) {
        return out;
    }

    // Control Request Control (pduType2 = 20, action = 1)
    QByteArray reqCtrlData;
    appendU16LE(reqCtrlData, 1);
    appendU16LE(reqCtrlData, 0);
    appendU32LE(reqCtrlData, 0);
    if (!sendAll(fd, buildShareDataPdu(shareId, userId, 20, reqCtrlData))) {
        return out;
    }

    // Font List PDU (pduType2 = 39)
    QByteArray fontData;
    appendU16LE(fontData, 0); // numberFonts
    appendU16LE(fontData, 0); // totalNumFonts
    appendU16LE(fontData, 0x0003); // listFlags = FIRST | LAST
    appendU16LE(fontData, 50); // entrySize
    if (!sendAll(fd, buildShareDataPdu(shareId, userId, 39, fontData))) {
        return out;
    }

    out.userId = userId;
    out.shareId = shareId;
    out.sentFinalize = true;
    return out;
}

QByteArray recvRdpPdu(int fd, int timeoutMs = 200)
{
    char b0 = 0;
    if (!recvExact(fd, &b0, 1, timeoutMs)) {
        return {};
    }
    const uint8_t first = static_cast<uint8_t>(b0);
    if (first == 0x03) {
        char hdr[3] = {};
        if (!recvExact(fd, hdr, 3, timeoutMs)) {
            return {};
        }
        const uint16_t totalLen = static_cast<uint16_t>((static_cast<uint8_t>(hdr[1]) << 8) | static_cast<uint8_t>(hdr[2]));
        if (totalLen < 4) {
            return {};
        }
        QByteArray pkt(totalLen, Qt::Uninitialized);
        pkt[0] = b0;
        std::memcpy(pkt.data() + 1, hdr, 3);
        if (totalLen > 4 && !recvExact(fd, pkt.data() + 4, totalLen - 4, timeoutMs)) {
            return {};
        }
        return pkt;
    }

    // FastPath output PDU
    char b1 = 0;
    if (!recvExact(fd, &b1, 1, timeoutMs)) {
        return {};
    }
    uint16_t totalLen = 0;
    int hdrLen = 2;
    QByteArray pkt;
    pkt.append(b0);
    pkt.append(b1);
    if (static_cast<uint8_t>(b1) & 0x80) {
        char b2 = 0;
        if (!recvExact(fd, &b2, 1, timeoutMs)) {
            return {};
        }
        pkt.append(b2);
        hdrLen = 3;
        totalLen = static_cast<uint16_t>(((static_cast<uint8_t>(b1) & 0x7Fu) << 8) | static_cast<uint8_t>(b2));
    } else {
        totalLen = static_cast<uint8_t>(b1);
    }
    if (totalLen < hdrLen) {
        return {};
    }
    if (totalLen > hdrLen) {
        const int rem = totalLen - hdrLen;
        QByteArray tail(rem, Qt::Uninitialized);
        if (!recvExact(fd, tail.data(), static_cast<size_t>(rem), timeoutMs)) {
            return {};
        }
        pkt.append(tail);
    }
    return pkt;
}

QByteArray wrapStaticVirtualChannelPdu(uint16_t userId, uint16_t channelId, const QByteArray &payload)
{
    QByteArray svc;
    appendU32LE(svc, static_cast<uint32_t>(payload.size()));
    appendU32LE(svc, 0x00000003u); // CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST
    svc.append(payload);
    return wrapMcsSendDataRequest(userId, channelId, svc);
}

void appendDvcChannelId(QByteArray &buf, uint8_t cbId, uint32_t channelId)
{
    if (cbId == 0) {
        appendU8(buf, static_cast<uint8_t>(channelId & 0xFF));
    } else if (cbId == 1) {
        appendU16LE(buf, static_cast<uint16_t>(channelId & 0xFFFF));
    } else {
        appendU32LE(buf, channelId);
    }
}

QByteArray buildRdpGfxCapsAdvertiseDvc(uint16_t userId, uint8_t cbId, uint32_t gfxDvcId)
{
    QByteArray gfx;
    appendU16LE(gfx, 0x0012); // RDPGFX_CMDID_CAPSADVERTISE
    appendU16LE(gfx, 0);
    appendU32LE(gfx, 8 + 2 + 12); // pduLength
    appendU16LE(gfx, 1); // capsSetCount
    appendU32LE(gfx, 0x000A0701u); // RDPGFX_CAPVERSION_107
    appendU32LE(gfx, 4); // capsDataLength
    appendU32LE(gfx, 0x00000080u); // RDPGFX_CAPS_FLAG_SCALEDMAP_DISABLE

    QByteArray dvc;
    appendU8(dvc, static_cast<uint8_t>((0x03u << 4) | (cbId & 0x03u))); // DYNVC_DATA
    appendDvcChannelId(dvc, cbId, gfxDvcId);
    dvc.append(gfx);
    return wrapStaticVirtualChannelPdu(userId, 1005, dvc);
}

QByteArray buildRdpGfxFrameAckDvc(uint16_t userId, uint8_t cbId, uint32_t gfxDvcId, uint32_t frameId, uint32_t totalDecoded, uint32_t queueDepth = 0)
{
    QByteArray gfx;
    appendU16LE(gfx, 0x000D); // RDPGFX_CMDID_FRAMEACKNOWLEDGE
    appendU16LE(gfx, 0);
    appendU32LE(gfx, 8 + 12);
    appendU32LE(gfx, queueDepth);
    appendU32LE(gfx, frameId);
    appendU32LE(gfx, totalDecoded);

    QByteArray dvc;
    appendU8(dvc, static_cast<uint8_t>((0x03u << 4) | (cbId & 0x03u))); // DYNVC_DATA
    appendDvcChannelId(dvc, cbId, gfxDvcId);
    dvc.append(gfx);
    return wrapStaticVirtualChannelPdu(userId, 1005, dvc);
}

QByteArray buildFastPathScancodePdu(uint8_t scancode, bool release, bool extended = false)
{
    uint8_t eventFlags = 0;
    if (release) {
        eventFlags |= 0x01; // FASTPATH_INPUT_KBDFLAGS_RELEASE
    }
    if (extended) {
        eventFlags |= 0x02; // FASTPATH_INPUT_KBDFLAGS_EXTENDED
    }
    QByteArray pdu;
    appendU8(pdu, 0x04); // action=0 (FastPath), numEvents=1
    appendU8(pdu, 4); // total length = 4 bytes
    appendU8(pdu, eventFlags); // eventCode=0 (SCANCODE) | eventFlags
    appendU8(pdu, scancode);
    return pdu;
}

QByteArray buildFastPathMousePdu(uint16_t pointerFlags, uint16_t x, uint16_t y)
{
    QByteArray pdu;
    appendU8(pdu, 0x04); // action=0 (FastPath), numEvents=1
    appendU8(pdu, 9); // total length = 2 + 1 + 6 = 9 bytes
    appendU8(pdu, 0x20); // eventCode=1 (MOUSE) << 5
    appendU16LE(pdu, pointerFlags);
    appendU16LE(pdu, x);
    appendU16LE(pdu, y);
    return pdu;
}

bool asciiToAtSet1Scancode(char c, uint8_t &scancode, bool &needShift)
{
    needShift = false;
    switch (c) {
    case 'a':
    case 'A':
        scancode = 0x1E;
        needShift = (c == 'A');
        return true;
    case 'b':
    case 'B':
        scancode = 0x30;
        needShift = (c == 'B');
        return true;
    case 'c':
    case 'C':
        scancode = 0x2E;
        needShift = (c == 'C');
        return true;
    case 'd':
    case 'D':
        scancode = 0x20;
        needShift = (c == 'D');
        return true;
    case 'e':
    case 'E':
        scancode = 0x12;
        needShift = (c == 'E');
        return true;
    case 'f':
    case 'F':
        scancode = 0x21;
        needShift = (c == 'F');
        return true;
    case 'g':
    case 'G':
        scancode = 0x22;
        needShift = (c == 'G');
        return true;
    case 'h':
    case 'H':
        scancode = 0x23;
        needShift = (c == 'H');
        return true;
    case 'i':
    case 'I':
        scancode = 0x17;
        needShift = (c == 'I');
        return true;
    case 'j':
    case 'J':
        scancode = 0x24;
        needShift = (c == 'J');
        return true;
    case 'k':
    case 'K':
        scancode = 0x25;
        needShift = (c == 'K');
        return true;
    case 'l':
    case 'L':
        scancode = 0x26;
        needShift = (c == 'L');
        return true;
    case 'm':
    case 'M':
        scancode = 0x32;
        needShift = (c == 'M');
        return true;
    case 'n':
    case 'N':
        scancode = 0x31;
        needShift = (c == 'N');
        return true;
    case 'o':
    case 'O':
        scancode = 0x18;
        needShift = (c == 'O');
        return true;
    case 'p':
    case 'P':
        scancode = 0x19;
        needShift = (c == 'P');
        return true;
    case 'q':
    case 'Q':
        scancode = 0x10;
        needShift = (c == 'Q');
        return true;
    case 'r':
    case 'R':
        scancode = 0x13;
        needShift = (c == 'R');
        return true;
    case 's':
    case 'S':
        scancode = 0x1F;
        needShift = (c == 'S');
        return true;
    case 't':
    case 'T':
        scancode = 0x14;
        needShift = (c == 'T');
        return true;
    case 'u':
    case 'U':
        scancode = 0x16;
        needShift = (c == 'U');
        return true;
    case 'v':
    case 'V':
        scancode = 0x2F;
        needShift = (c == 'V');
        return true;
    case 'w':
    case 'W':
        scancode = 0x11;
        needShift = (c == 'W');
        return true;
    case 'x':
    case 'X':
        scancode = 0x2D;
        needShift = (c == 'X');
        return true;
    case 'y':
    case 'Y':
        scancode = 0x15;
        needShift = (c == 'Y');
        return true;
    case 'z':
    case 'Z':
        scancode = 0x2C;
        needShift = (c == 'Z');
        return true;
    case '1':
    case '!':
        scancode = 0x02;
        needShift = (c == '!');
        return true;
    case '2':
        scancode = 0x03;
        return true;
    case '3':
        scancode = 0x04;
        return true;
    case '4':
        scancode = 0x05;
        return true;
    case '5':
        scancode = 0x06;
        return true;
    case '6':
        scancode = 0x07;
        return true;
    case '7':
        scancode = 0x08;
        return true;
    case '8':
        scancode = 0x09;
        return true;
    case '9':
        scancode = 0x0A;
        return true;
    case '0':
        scancode = 0x0B;
        return true;
    default:
        return false;
    }
}

bool sendFastPathString(int fd, const QByteArray &ascii)
{
    for (const char c : ascii) {
        uint8_t sc = 0;
        bool shift = false;
        if (!asciiToAtSet1Scancode(c, sc, shift)) {
            return false;
        }
        if (shift && !sendAll(fd, buildFastPathScancodePdu(0x2A, false))) {
            return false;
        }
        if (!sendAll(fd, buildFastPathScancodePdu(sc, false)) || !sendAll(fd, buildFastPathScancodePdu(sc, true))) {
            return false;
        }
        if (shift && !sendAll(fd, buildFastPathScancodePdu(0x2A, true))) {
            return false;
        }
    }
    return true;
}

} // namespace

class VmConnectAuthTest : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_tempDir;
    std::filesystem::path m_certPath;
    std::filesystem::path m_keyPath;

    std::unique_ptr<KRdp::Server> makeTestServer(bool inBandGreeter)
    {
        auto server = std::make_unique<KRdp::Server>();
        server->setTransport(KRdp::Server::Transport::Vsock);
        server->setHyperVMode(true);
        server->setInBandGreeterEnabled(inBandGreeter);
        server->setPort(34398);
        server->setAllowedVsockPeerCid(2);
        server->setUsePAMAuthentication(true);
        server->setTlsCertificate(m_certPath);
        server->setTlsCertificateKey(m_keyPath);
        // Add a test non-root user (and intentionally try adding a root user to verify it is still blocked!)
        server->addUser(KRdp::User{QStringLiteral("foxguest"), QStringLiteral("ValidGuestPass!99"), false});
        server->addUser(KRdp::User{QStringLiteral("root"), QStringLiteral("ValidGuestPass!99"), false});
        return server;
    }

private Q_SLOTS:
    void initTestCase()
    {
        QVERIFY(m_tempDir.isValid());
        m_certPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.crt")).toStdString());
        m_keyPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.key")).toStdString());

        QProcess openssl;
        openssl.start(QStringLiteral("openssl"),
                      {
                          QStringLiteral("req"),
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
                          QStringLiteral("/CN=krdp-vmconnect-auth-test"),
                      });
        QVERIFY(openssl.waitForFinished(15000));
        QCOMPARE(openssl.exitCode(), 0);
    }

    void testVmConnectRejectsEmptyCredentialsWhenGreeterDisabled()
    {
        auto server = makeTestServer(false);
        server->setAuthThrottlePolicy(1000, 60000, 100); // soak intentionally sends 50 invalid auth cycles
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, false, 2, 50001};
        KRdp::RdpConnection conn(server.get(), fds[0], info);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QString(), QString());
        QVERIFY(ho.negoSucceeded);
        QCOMPARE(ho.selectedProtocol, 0x00000001u); // PROTOCOL_SSL
        QVERIFY((ho.negoFlags & 0x0Bu) == 0x0Bu);
        QVERIFY(ho.mcsSucceeded);
        QVERIFY(ho.sentClientInfo);
        QVERIFY(ho.sentFinalize);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(conn.authState(), KRdp::RdpConnection::AuthState::Unauthenticated);

        ::close(fds[1]);
        server->stop();
    }

    void testVmConnectRejectsInvalidPassword()
    {
        auto server = makeTestServer(true); // Even with in-band greeter ON, explicit wrong password MUST fail!
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50002};
        KRdp::RdpConnection conn(server.get(), fds[0], info);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QStringLiteral("foxguest"), QStringLiteral("WrongPassword!"));
        QVERIFY(ho.negoSucceeded);
        QVERIFY(ho.mcsSucceeded);
        QVERIFY(ho.sentFinalize);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(conn.authState(), KRdp::RdpConnection::AuthState::Unauthenticated);

        ::close(fds[1]);
        server->stop();
    }

    void testVmConnectRejectsRootLogin()
    {
        auto server = makeTestServer(true);
        QVERIFY(server->start());

        for (const QString &rootVariant : {QStringLiteral("root"), QStringLiteral("DOMAIN\\root"), QStringLiteral(".\\ROOT")}) {
            int fds[2] = {-1, -1};
            QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

            KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50003};
            KRdp::RdpConnection conn(server.get(), fds[0], info);

            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
            const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], rootVariant, QStringLiteral("ValidGuestPass!99"));
            QVERIFY(ho.negoSucceeded);
            QVERIFY(ho.mcsSucceeded);
            QVERIFY(ho.sentFinalize);

            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
            QVERIFY(!conn.isAuthenticated());
            ::close(fds[1]);
        }

        server->stop();
    }

    void testVmConnectAcceptsValidCredentials()
    {
        auto server = makeTestServer(true);
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50004};
        KRdp::RdpConnection conn(server.get(), fds[0], info);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QStringLiteral("FOXCORE\\foxguest"), QStringLiteral("ValidGuestPass!99"));
        QVERIFY(ho.negoSucceeded);
        QCOMPARE(ho.selectedProtocol, 0x00000001u);
        QVERIFY(ho.mcsSucceeded);
        QVERIFY(ho.sentFinalize);

        QTRY_VERIFY_WITH_TIMEOUT(conn.state() == KRdp::RdpConnection::State::Activated || conn.state() == KRdp::RdpConnection::State::Streaming, 3000);
        QVERIFY(conn.isAuthenticated());
        QCOMPARE(conn.authState(), KRdp::RdpConnection::AuthState::Authenticated);
        QCOMPARE(conn.authenticatedUser(), QStringLiteral("foxguest"));

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        server->stop();
    }

    void testVmConnectEmptyPasswordEntersIsolatedInBandGreeterAndAuthenticates()
    {
        auto server = makeTestServer(true);
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50005};
        KRdp::RdpConnection conn(server.get(), fds[0], info);
        QSignalSpy authSpy(&conn, &KRdp::RdpConnection::authenticatedChanged);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        // Simulate vmconnect.exe sending empty credentials in TS_INFO_PACKET
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QString(), QString());
        QVERIFY(ho.negoSucceeded);
        QVERIFY(ho.mcsSucceeded);
        QVERIFY(ho.sentFinalize);

        // Must enter PendingInBandGreeter and MUST NOT be authenticated or initialize Clipboard/Audio!
        QTRY_COMPARE_WITH_TIMEOUT(conn.authState(), KRdp::RdpConnection::AuthState::PendingInBandGreeter, 3000);
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(authSpy.count(), 0);
        QVERIFY(!conn.clipboard()->enabled());
        QVERIFY(!conn.audioStream()->enabled());
        QVERIFY(!conn.audioInputStream()->enabled());

        // Start greeter directly (simulating RDPGFX open) and verify frame rendering + auth controls
        auto *greeter = conn.inBandGreeter();
        QVERIFY(greeter != nullptr);
        greeter->start(QSize(1280, 720), QStringLiteral("foxguest"));
        QVERIFY(greeter->isActive());
        const QImage rendered = greeter->renderFrame();
        QCOMPARE(rendered.size(), QSize(1280, 720));

        // 1. Root rejected in greeter
        QVERIFY(!greeter->submitCredentials(QStringLiteral("root"), QStringLiteral("ValidGuestPass!99")));
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(greeter->failedAttempts(), 1);

        // 2. Cooldown blocks immediate rapid retry
        QVERIFY(!greeter->submitCredentials(QStringLiteral("foxguest"), QStringLiteral("ValidGuestPass!99")));
        QVERIFY(!conn.isAuthenticated());

        // 3. After cooldown, invalid password rejected
        QTest::qWait(KRdp::InBandGreeter::FailureCooldownMs + 50);
        QVERIFY(!greeter->submitCredentials(QStringLiteral("foxguest"), QStringLiteral("WrongPass")));
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(greeter->failedAttempts(), 2);

        // 4. After cooldown, type valid credentials via Unicode key events + Return into InBandGreeter!
        QTest::qWait(KRdp::InBandGreeter::FailureCooldownMs + 50);
        const QString validPass = QStringLiteral("ValidGuestPass!99");
        for (const QChar ch : validPass) {
            const uint32_t keysym = static_cast<uint32_t>(ch.unicode()); // Latin-1 Unicode == XKB keysym
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyPress, 0, Qt::NoModifier, 0, keysym, 0));
            greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyRelease, 0, Qt::NoModifier, 0, keysym, 0));
        }
        greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyPress, 0, Qt::NoModifier, 0, 0xFF0D /* XKB_KEY_Return */, 0));
        greeter->handleInputEvent(std::make_shared<QKeyEvent>(QEvent::KeyRelease, 0, Qt::NoModifier, 0, 0xFF0D, 0));

        QTRY_VERIFY_WITH_TIMEOUT(conn.isAuthenticated(), 2000);
        QCOMPARE(conn.authState(), KRdp::RdpConnection::AuthState::Authenticated);
        QCOMPARE(authSpy.count(), 1);
        QVERIFY(!greeter->isActive());

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        server->stop();
    }

    void testVmConnectInBandGreeterLocksOutAfterMaxAttempts()
    {
        auto server = makeTestServer(true);
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50006};
        KRdp::RdpConnection conn(server.get(), fds[0], info);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QString(), QString());
        QVERIFY(ho.sentFinalize);

        QTRY_COMPARE_WITH_TIMEOUT(conn.authState(), KRdp::RdpConnection::AuthState::PendingInBandGreeter, 3000);
        auto *greeter = conn.inBandGreeter();
        greeter->start(QSize(1280, 720), QStringLiteral("foxguest"));

        for (int i = 0; i < KRdp::InBandGreeter::MaxFailedAttempts; ++i) {
            if (i > 0) {
                QTest::qWait(KRdp::InBandGreeter::FailureCooldownMs + 50);
            }
            QVERIFY(!greeter->submitCredentials(QStringLiteral("foxguest"), QStringLiteral("WrongPass")));
        }

        // After 5 failed attempts, connection must be closed automatically and remain unauthenticated
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        QVERIFY(!conn.isAuthenticated());

        ::close(fds[1]);
        server->stop();
    }

    void testVmConnectInBandGreeterWireGfxAndInput()
    {
        auto server = makeTestServer(true);
        QVERIFY(server->start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

        KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 50007};
        KRdp::RdpConnection conn(server.get(), fds[0], info);
        QSignalSpy authSpy(&conn, &KRdp::RdpConnection::authenticatedChanged);

        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 3000);
        const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QString(), QString());
        QVERIFY(ho.negoSucceeded);
        QVERIFY(ho.mcsSucceeded);
        QVERIFY(ho.sentFinalize);

        QTRY_COMPARE_WITH_TIMEOUT(conn.authState(), KRdp::RdpConnection::AuthState::PendingInBandGreeter, 3000);
        QVERIFY(!conn.isAuthenticated());

        // Drive real drdynvc + RDPGFX wire protocol on fds[1], including Windows VMConnect
        // double-CapsAdvertise, coalesced FrameAcknowledge, and real FastPath mouse/keyboard input.
        std::unique_ptr<ZGFX_CONTEXT, decltype(&zgfx_context_free)> zgfx(zgfx_context_new(FALSE), zgfx_context_free);
        QVERIFY(zgfx != nullptr);

        QByteArray svcReassembly;
        QByteArray dvcReassembly;
        uint32_t dvcExpectedLen = 0;
        bool gfxOpened = false;
        uint8_t gfxCbId = 0;
        uint32_t gfxDvcId = 0;
        std::vector<uint16_t> gfxCmdIds;
        std::vector<uint32_t> endFrameIds;

        auto readLenField = [](const QByteArray &buf, int &off, uint8_t kind) -> uint32_t {
            if (kind == 0 && off + 1 <= buf.size()) {
                return static_cast<uint8_t>(buf[off++]);
            }
            if (kind == 1 && off + 2 <= buf.size()) {
                const uint32_t v = static_cast<uint8_t>(buf[off]) | (static_cast<uint32_t>(static_cast<uint8_t>(buf[off + 1])) << 8);
                off += 2;
                return v;
            }
            if (kind == 2 && off + 4 <= buf.size()) {
                const uint32_t v = static_cast<uint8_t>(buf[off]) | (static_cast<uint32_t>(static_cast<uint8_t>(buf[off + 1])) << 8)
                    | (static_cast<uint32_t>(static_cast<uint8_t>(buf[off + 2])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(buf[off + 3])) << 24);
                off += 4;
                return v;
            }
            return 0;
        };

        auto parseGfxStream = [&](const QByteArray &compressed) {
            BYTE *uncomp = nullptr;
            UINT32 uncompLen = 0;
            const int rc = zgfx_decompress(zgfx.get(),
                                           reinterpret_cast<const BYTE *>(compressed.constData()),
                                           static_cast<UINT32>(compressed.size()),
                                           &uncomp,
                                           &uncompLen,
                                           0);
            if (rc < 0 || !uncomp || uncompLen < 8) {
                if (uncomp) {
                    free(uncomp);
                }
                return;
            }
            size_t off = 0;
            while (off + 8 <= uncompLen) {
                const uint16_t cmdId = static_cast<uint16_t>(uncomp[off] | (uncomp[off + 1] << 8));
                const uint32_t pduLen = static_cast<uint32_t>(uncomp[off + 4]) | (static_cast<uint32_t>(uncomp[off + 5]) << 8)
                    | (static_cast<uint32_t>(uncomp[off + 6]) << 16) | (static_cast<uint32_t>(uncomp[off + 7]) << 24);
                if (pduLen < 8 || off + pduLen > uncompLen) {
                    break;
                }
                gfxCmdIds.push_back(cmdId);
                if (cmdId == 0x000C && pduLen >= 12) { // RDPGFX_CMDID_ENDFRAME
                    const uint32_t fid = static_cast<uint32_t>(uncomp[off + 8]) | (static_cast<uint32_t>(uncomp[off + 9]) << 8)
                        | (static_cast<uint32_t>(uncomp[off + 10]) << 16) | (static_cast<uint32_t>(uncomp[off + 11]) << 24);
                    endFrameIds.push_back(fid);
                }
                off += pduLen;
            }
            free(uncomp);
        };

        auto pumpServerPdus = [&](int durationMs, const std::function<bool()> &stopWhen) {
            QElapsedTimer timer;
            timer.start();
            while (timer.elapsed() < durationMs) {
                QCoreApplication::processEvents();
                if (stopWhen && stopWhen()) {
                    return true;
                }
                const QByteArray pkt = recvRdpPdu(fds[1], 40);
                if (pkt.isEmpty()) {
                    continue;
                }
                if (static_cast<uint8_t>(pkt[0]) != 0x03 || pkt.size() < 16 || static_cast<uint8_t>(pkt[7]) != 0x68) {
                    continue;
                }
                const uint16_t mcsChan = static_cast<uint16_t>((static_cast<uint8_t>(pkt[10]) << 8) | static_cast<uint8_t>(pkt[11]));
                if (mcsChan != 1005) {
                    continue;
                }
                int off = 13; // 7 (TPKT+X224) + 1 (0x68) + 2 (initiator) + 2 (chan) + 1 (flags)
                if (off >= pkt.size()) {
                    continue;
                }
                if (static_cast<uint8_t>(pkt[off]) & 0x80) {
                    off += 2;
                } else {
                    off += 1;
                }
                if (off + 8 > pkt.size()) {
                    continue;
                }
                const uint32_t svcFlags = static_cast<uint32_t>(static_cast<uint8_t>(pkt[off + 4]))
                    | (static_cast<uint32_t>(static_cast<uint8_t>(pkt[off + 5])) << 8) | (static_cast<uint32_t>(static_cast<uint8_t>(pkt[off + 6])) << 16)
                    | (static_cast<uint32_t>(static_cast<uint8_t>(pkt[off + 7])) << 24);
                const QByteArray chunk = pkt.mid(off + 8);
                if (svcFlags & 0x01u) {
                    svcReassembly.clear();
                }
                svcReassembly.append(chunk);
                if (!(svcFlags & 0x02u)) {
                    continue;
                }

                const QByteArray dvc = svcReassembly;
                svcReassembly.clear();
                if (dvc.isEmpty()) {
                    continue;
                }
                const uint8_t hdr = static_cast<uint8_t>(dvc[0]);
                const uint8_t cmd = (hdr >> 4) & 0x0Fu;
                const uint8_t sp = (hdr >> 2) & 0x03u;
                const uint8_t cbId = hdr & 0x03u;
                int doff = 1;

                if (cmd == 5) {
                    // DYNVC_CAPS_VERSION -> reply DYNVC_CAPS_RESPONSE (v2)
                    QByteArray capsRsp = QByteArray::fromHex("50000200");
                    sendAll(fds[1], wrapStaticVirtualChannelPdu(ho.userId, 1005, capsRsp));
                } else if (cmd == 1) {
                    // DYNVC_CREATE_REQ
                    const uint32_t chId = readLenField(dvc, doff, cbId);
                    const QByteArray chName = dvc.mid(doff).split('\0').first();
                    QByteArray createRsp;
                    appendU8(createRsp, static_cast<uint8_t>((1u << 4) | cbId));
                    appendDvcChannelId(createRsp, cbId, chId);
                    appendU32LE(createRsp, 0); // STATUS_SUCCESS
                    sendAll(fds[1], wrapStaticVirtualChannelPdu(ho.userId, 1005, createRsp));
                    if (chName == "Microsoft::Windows::RDS::Graphics") {
                        gfxOpened = true;
                        gfxCbId = cbId;
                        gfxDvcId = chId;
                    }
                } else if (cmd == 2 || cmd == 3) {
                    const uint32_t chId = readLenField(dvc, doff, cbId);
                    if (!gfxOpened || chId != gfxDvcId) {
                        continue;
                    }
                    if (cmd == 2) {
                        dvcExpectedLen = readLenField(dvc, doff, sp);
                        dvcReassembly = dvc.mid(doff);
                    } else if (dvcExpectedLen > 0) {
                        dvcReassembly.append(dvc.mid(doff));
                    } else {
                        parseGfxStream(dvc.mid(doff));
                        continue;
                    }
                    if (dvcExpectedLen > 0 && static_cast<uint32_t>(dvcReassembly.size()) >= dvcExpectedLen) {
                        parseGfxStream(dvcReassembly.left(static_cast<int>(dvcExpectedLen)));
                        dvcReassembly.clear();
                        dvcExpectedLen = 0;
                    }
                }
            }
            return stopWhen ? stopWhen() : true;
        };

        // 1. Wait for drdynvc + Microsoft::Windows::RDS::Graphics channel creation
        QVERIFY(pumpServerPdus(4000, [&]() {
            return gfxOpened;
        }));

        // 2. Send CapsAdvertise #1 -> verify CapsConfirm + Frame 1 (frameId starts at 1, not 0!)
        QVERIFY(sendAll(fds[1], buildRdpGfxCapsAdvertiseDvc(ho.userId, gfxCbId, gfxDvcId)));
        QVERIFY(pumpServerPdus(4000, [&]() {
            return !endFrameIds.empty();
        }));
        QCOMPARE(endFrameIds.front(), 1u);
        QVERIFY(std::find(gfxCmdIds.begin(), gfxCmdIds.end(), 0x0013u /* CAPSCONFIRM */) != gfxCmdIds.end());
        QVERIFY(std::find(gfxCmdIds.begin(), gfxCmdIds.end(), 0x0002u /* WIRETOSURFACE_2 */) != gfxCmdIds.end());

        // 3. Simulate Windows VMConnect double-CapsAdvertise (#2) right after Frame 1!
        const size_t cmdsBeforeReAdv = gfxCmdIds.size();
        const size_t framesBeforeReAdv = endFrameIds.size();
        QVERIFY(sendAll(fds[1], buildRdpGfxCapsAdvertiseDvc(ho.userId, gfxCbId, gfxDvcId)));
        QVERIFY(pumpServerPdus(4000, [&]() {
            return endFrameIds.size() > framesBeforeReAdv;
        }));

        // Verify NO DeleteEncodingContext (0x0003) or DeleteSurface (0x000A) was sent BEFORE CapsConfirm #2!
        bool sawCapsConfirm2 = false;
        for (size_t i = cmdsBeforeReAdv; i < gfxCmdIds.size(); ++i) {
            if (gfxCmdIds[i] == 0x0013u) {
                sawCapsConfirm2 = true;
                break;
            }
            QVERIFY2(gfxCmdIds[i] != 0x0003u && gfxCmdIds[i] != 0x000Au,
                     "DeleteEncodingContext/DeleteSurface must not be sent before CapsConfirm on re-advertisement");
        }
        QVERIFY(sawCapsConfirm2);

        // 4. Test coalesced FrameAcknowledge + real wire FastPath Mouse & Keyboard input!
        // Trigger 2 focus-change redraws by clicking Username field (640, 332) then Password field (640, 404),
        // acknowledge ONLY the latest frameId, and verify subsequent frames still flow without stalling.
        const size_t framesBeforeClicks = endFrameIds.size();
        QVERIFY(sendAll(fds[1], buildFastPathMousePdu(0x9000 /* DOWN|BUTTON1 */, 640, 332)));
        QVERIFY(sendAll(fds[1], buildFastPathMousePdu(0x1000 /* BUTTON1 up */, 640, 332)));
        QVERIFY(pumpServerPdus(3000, [&]() {
            return endFrameIds.size() > framesBeforeClicks;
        }));
        const uint32_t latestBeforeAck = endFrameIds.back();
        // Coalesced ACK: only acknowledge latest frameId (must clear all older pending frames too!)
        QVERIFY(sendAll(fds[1], buildRdpGfxFrameAckDvc(ho.userId, gfxCbId, gfxDvcId, latestBeforeAck, latestBeforeAck)));

        // Clear prefilled username via Backspace scancodes (0x0E), type "foxguest", Tab (0x0F),
        // type "ValidGuestPass!99", press Return (0x1C) — 100% over real FastPath wire PDUs!
        for (int i = 0; i < 16; ++i) {
            QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x0E, false)));
            QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x0E, true)));
        }
        QVERIFY(sendFastPathString(fds[1], QByteArrayLiteral("foxguest")));
        QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x0F, false))); // Tab -> Password
        QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x0F, true)));
        // Acknowledge frames generated while typing username so window stays open
        pumpServerPdus(200, nullptr);
        if (!endFrameIds.empty()) {
            QVERIFY(sendAll(fds[1], buildRdpGfxFrameAckDvc(ho.userId, gfxCbId, gfxDvcId, endFrameIds.back(), endFrameIds.back())));
        }

        QVERIFY(sendFastPathString(fds[1], QByteArrayLiteral("ValidGuestPass!99")));
        QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x1C, false))); // Return -> Submit
        QVERIFY(sendAll(fds[1], buildFastPathScancodePdu(0x1C, true)));

        QVERIFY(pumpServerPdus(4000, [&]() {
            return conn.isAuthenticated();
        }));
        QVERIFY(conn.isAuthenticated());
        QCOMPARE(conn.authState(), KRdp::RdpConnection::AuthState::Authenticated);
        QCOMPARE(conn.authenticatedUser(), QStringLiteral("foxguest"));
        QCOMPARE(authSpy.count(), 1);
        QVERIFY(!conn.inBandGreeter()->isActive());

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 3000);
        server->stop();
    }

    void testVmConnect100CycleSoakNoLeak()
    {
        auto readProcStatusValue = [](const QByteArray &prefix) -> qint64 {
            QFile f(QStringLiteral("/proc/self/status"));
            if (!f.open(QIODevice::ReadOnly)) {
                return -1;
            }
            const QList<QByteArray> lines = f.readAll().split('\n');
            for (const QByteArray &line : lines) {
                if (line.startsWith(prefix)) {
                    const auto parts = line.simplified().split(' ');
                    if (parts.size() >= 2) {
                        return parts[1].toLongLong();
                    }
                }
            }
            return -1;
        };
        auto readRssKb = [&]() -> qint64 {
            return readProcStatusValue("VmRSS:");
        };
        auto readThreads = [&]() -> int {
            return static_cast<int>(readProcStatusValue("Threads:"));
        };
        auto readFdCount = []() -> int {
            return static_cast<int>(QDir(QStringLiteral("/proc/self/fd")).entryList(QDir::NoDotAndDotDot | QDir::AllEntries).size());
        };

        auto server = makeTestServer(false);
        server->setAuthThrottlePolicy(1000, 60000, 100); // soak intentionally sends 50 invalid auth cycles
        QVERIFY(server->start());

        qint64 rssWarmKb = -1;
        int fdsWarm = -1;
        int threadsWarm = -1;

        for (int i = 0; i < 100; ++i) {
            int fds[2] = {-1, -1};
            QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

            KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, false, 2, static_cast<quint32>(51000 + i)};
            {
                KRdp::RdpConnection conn(server.get(), fds[0], info);

                QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);
                const bool validCycle = (i % 2 == 0);
                const HandshakeOutcome ho =
                    runHyperVWireHandshake(fds[1], QStringLiteral("foxguest"), validCycle ? QStringLiteral("ValidGuestPass!99") : QStringLiteral("WrongPass"));
                QVERIFY(ho.negoSucceeded);
                QVERIFY(ho.mcsSucceeded);
                QVERIFY(ho.sentFinalize);

                if (validCycle) {
                    QTRY_VERIFY_WITH_TIMEOUT(conn.isAuthenticated(), 2000);
                    conn.close();
                } else {
                    QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
                    QVERIFY(!conn.isAuthenticated());
                }
                ::close(fds[1]);
                QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
            }
            // Capture warm-up baseline after cycle 10 (allocator pools settled)
            if (i == 9) {
                rssWarmKb = readRssKb();
                fdsWarm = readFdCount();
                threadsWarm = readThreads();
            }
        }

        const qint64 rssEndKb = readRssKb();
        const int fdsEnd = readFdCount();
        const int threadsEnd = readThreads();
        QVERIFY2(rssWarmKb > 0 && rssEndKb > 0, "Failed to read /proc/self/status VmRSS");
        QVERIFY2(threadsWarm > 0 && threadsEnd > 0, "Failed to read /proc/self/status Threads");
        const double rssGrowthMib = static_cast<double>(rssEndKb - rssWarmKb) / 1024.0;
        qInfo().noquote().nospace() << "VMCONNECT_SOAK_100: rss_warm_mib=" << QString::number(static_cast<double>(rssWarmKb) / 1024.0, 'f', 2)
                                    << " rss_end_mib=" << QString::number(static_cast<double>(rssEndKb) / 1024.0, 'f', 2)
                                    << " rss_delta_mib=" << QString::number(rssGrowthMib, 'f', 2) << " fds_warm=" << fdsWarm << " fds_end=" << fdsEnd
                                    << " threads_warm=" << threadsWarm << " threads_end=" << threadsEnd;

        // Assert zero FD leak (<= 2 tolerance for transient eventfd), zero thread leak, and bounded RSS (< 16 MiB over 90 cycles)
        QVERIFY2(fdsEnd - fdsWarm <= 2, qPrintable(QStringLiteral("FD leak detected: warm=%1 end=%2").arg(fdsWarm).arg(fdsEnd)));
        QVERIFY2(threadsEnd <= threadsWarm + 1, qPrintable(QStringLiteral("Thread leak detected: warm=%1 end=%2").arg(threadsWarm).arg(threadsEnd)));
        QVERIFY2(rssGrowthMib < 16.0, qPrintable(QStringLiteral("Excessive RSS growth over 90 cycles: %1 MiB").arg(rssGrowthMib)));

        server->stop();
    }

    void testCrossConnectionAuthThrottlingAndUserBinding()
    {
        auto server = makeTestServer(true);
        // Lock out user after 3 failures across separate connections for 350 ms
        server->setAuthThrottlePolicy(3, 10000, 350);
        QVERIFY(server->start());

        // 3 separate connections each failing once as "foxguest" -> triggers cross-connection lockout
        for (int attempt = 0; attempt < 3; ++attempt) {
            int fds[2] = {-1, -1};
            QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
            KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, static_cast<quint32>(52000 + attempt)};
            KRdp::RdpConnection conn(server.get(), fds[0], info);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);
            const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QStringLiteral("foxguest"), QStringLiteral("WrongPass"));
            QVERIFY(ho.sentFinalize);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
            QVERIFY(!conn.isAuthenticated());
            QVERIFY(conn.authenticatedUser().isEmpty());
            ::close(fds[1]);
        }

        // 4th connection with VALID password must still be rejected while lockout is active!
        QVERIFY(!server->isAuthAttemptAllowed(QStringLiteral("foxguest")));
        {
            int fds[2] = {-1, -1};
            QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
            KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 52010};
            KRdp::RdpConnection conn(server.get(), fds[0], info);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);
            const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QStringLiteral("foxguest"), QStringLiteral("ValidGuestPass!99"));
            QVERIFY(ho.sentFinalize);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
            QVERIFY(!conn.isAuthenticated());
            QVERIFY(conn.authenticatedUser().isEmpty());
            ::close(fds[1]);
        }

        // After lockout window expires, valid login succeeds and binds authenticatedUser()
        QTest::qWait(400);
        QVERIFY(server->isAuthAttemptAllowed(QStringLiteral("foxguest")));

        // Verify bogus/disallowed username flooding does NOT lock out legitimate user "foxguest"
        // and keeps tracked auth throttle maps strictly bounded (no memory DoS).
        for (int i = 0; i < 600; ++i) {
            server->recordAuthFailure(QStringLiteral("bogus_user_%1").arg(i));
        }
        QVERIFY2(server->trackedAuthThrottleEntries() <= 512,
                 qPrintable(QStringLiteral("Unbounded auth throttle map: %1 entries").arg(server->trackedAuthThrottleEntries())));
        QVERIFY(server->isAuthAttemptAllowed(QStringLiteral("foxguest")));

        {
            int fds[2] = {-1, -1};
            QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
            KRdp::RdpConnection::TransportInfo info{KRdp::Server::Transport::Vsock, true, true, 2, 52011};
            KRdp::RdpConnection conn(server.get(), fds[0], info);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);
            const HandshakeOutcome ho = runHyperVWireHandshake(fds[1], QStringLiteral("FOXCORE\\foxguest"), QStringLiteral("ValidGuestPass!99"));
            QVERIFY(ho.sentFinalize);
            QTRY_VERIFY_WITH_TIMEOUT(conn.isAuthenticated(), 2000);
            QCOMPARE(conn.authenticatedUser(), QStringLiteral("foxguest"));
            QVERIFY(!conn.authenticatedViaPam());
            conn.close();
            ::close(fds[1]);
            QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
        }

        server->stop();
    }
};

QTEST_MAIN(VmConnectAuthTest)
#include "vmconnectauthtest.moc"
