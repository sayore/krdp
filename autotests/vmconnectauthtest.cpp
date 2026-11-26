// SPDX-FileCopyrightText: 2026 FOXCORE Integration
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QByteArray>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QKeyEvent>
#include <QProcess>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QtEndian>

#include <cstdint>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

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
    capInp[0] = 0x01; // INPUT_FLAG_SCANCODES
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

    out.sentFinalize = true;
    return out;
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

        // Must enter PendingInBandGreeter and MUST NOT be authenticated or initialize Clipboard!
        QTRY_COMPARE_WITH_TIMEOUT(conn.authState(), KRdp::RdpConnection::AuthState::PendingInBandGreeter, 3000);
        QVERIFY(!conn.isAuthenticated());
        QCOMPARE(authSpy.count(), 0);
        QVERIFY(!conn.clipboard()->enabled());

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
};

QTEST_MAIN(VmConnectAuthTest)
#include "vmconnectauthtest.moc"
