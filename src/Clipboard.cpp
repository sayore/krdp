// SPDX-FileCopyrightText: 2024 Akseli Lahtinen <akselmo@akselmo.dev>
// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Clipboard.h"

#include <cstring>
#include <limits>
#include <optional>
#include <vector>

#include <QBuffer>
#include <QColor>
#include <QImageReader>
#include <QPainter>
#include <QQueue>

#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/server/cliprdr.h>

#include "PeerContext_p.h"
#include "RdpConnection.h"

#include "krdp_logging.h"

using namespace Qt::StringLiterals;

namespace KRdp
{

namespace
{
constexpr uint32_t CfTextId = 1; // CF_TEXT
constexpr uint32_t CfDibId = 8; // CF_DIB
constexpr uint32_t CfUnicodeTextId = 13; // CF_UNICODETEXT
constexpr uint32_t CfDibV5Id = 17; // CF_DIBV5
constexpr uint32_t CustomPngFormatId = 0xD001u;
constexpr qsizetype MaxClipboardPayloadBytes = 32 * 1024 * 1024;
constexpr uint64_t MaxDecodedImageBytes = 64ull * 1024ull * 1024ull; // 64 MiB RGBA ceiling (~16.7M pixels; covers 5K, blocks 1 GiB PNG/BMP bombs)
constexpr int MaxClipboardImageDimension = 16384;

bool isSafeImageDimensions(int width, int height)
{
    if (width <= 0 || height <= 0 || width > MaxClipboardImageDimension || height > MaxClipboardImageDimension) {
        return false;
    }
    const uint64_t decodedRgbaBytes = static_cast<uint64_t>(width) * static_cast<uint64_t>(height) * 4ull;
    return decodedRgbaBytes <= MaxDecodedImageBytes;
}

uint16_t readU16LE(const QByteArray &buf, qsizetype offset)
{
    return static_cast<uint16_t>(static_cast<uint8_t>(buf[offset]) | (static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 1])) << 8));
}

uint32_t readU32LE(const QByteArray &buf, qsizetype offset)
{
    return static_cast<uint32_t>(static_cast<uint8_t>(buf[offset])) | (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + 1])) << 8)
        | (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + 2])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(buf[offset + 3])) << 24);
}

void writeU16LE(char *dst, uint16_t v)
{
    dst[0] = static_cast<char>(v & 0xFFu);
    dst[1] = static_cast<char>((v >> 8) & 0xFFu);
}

void writeU32LE(char *dst, uint32_t v)
{
    dst[0] = static_cast<char>(v & 0xFFu);
    dst[1] = static_cast<char>((v >> 8) & 0xFFu);
    dst[2] = static_cast<char>((v >> 16) & 0xFFu);
    dst[3] = static_cast<char>((v >> 24) & 0xFFu);
}

QImage extractServerImage(const QMimeData *data)
{
    if (!data) {
        return {};
    }
    if (data->hasImage()) {
        const QImage img = qvariant_cast<QImage>(data->imageData());
        if (!img.isNull() && isSafeImageDimensions(img.width(), img.height()) && static_cast<uint64_t>(img.sizeInBytes()) <= MaxDecodedImageBytes) {
            return img;
        }
    }
    if (data->hasFormat(u"image/png"_s)) {
        const QByteArray raw = data->data(u"image/png"_s);
        return Clipboard::decodeImageSafely(raw, "PNG");
    }
    return {};
}

bool isPngFormatName(const char *name)
{
    if (!name) {
        return false;
    }
    const QString s = QString::fromUtf8(name).trimmed();
    return s.compare(u"PNG"_s, Qt::CaseInsensitive) == 0 || s.compare(u"image/png"_s, Qt::CaseInsensitive) == 0;
}
} // namespace

class KRDP_NO_EXPORT Clipboard::Private
{
public:
    using CliprdrServerContextPtr = std::unique_ptr<CliprdrServerContext, decltype(&cliprdr_server_context_free)>;

    enum class FormatKind {
        UnicodeText,
        AnsiText,
        ImagePng,
        ImageDib,
    };

    struct PendingRequest {
        uint32_t formatId = 0;
        FormatKind kind = FormatKind::UnicodeText;
        bool isImageFallback = false;
        bool discarded = false;
    };

    Private(Clipboard *qq)
        : q(qq)
    {
    }

    Clipboard *q;

    uint32_t onClientCapabilities(const CLIPRDR_CAPABILITIES *capabilities);
    uint32_t onClientFormatList(const CLIPRDR_FORMAT_LIST *formatList);
    uint32_t onClientFormatListResponse(const CLIPRDR_FORMAT_LIST_RESPONSE *formatListResponse);
    uint32_t onClientFormatDataRequest(const CLIPRDR_FORMAT_DATA_REQUEST *formatDataRequest);
    uint32_t onClientFormatDataResponse(const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse);

    void requestNextPendingFormat();
    void finalizeStagedClientData();

    RdpConnection *session = nullptr;

    CliprdrServerContextPtr clipContext = CliprdrServerContextPtr(nullptr, cliprdr_server_context_free);

    bool enabled = false;
    // mstsc drops a format list sent before its capabilities response; hold until markClientReady()
    bool clientReady = false;
    void markClientReady()
    {
        if (clientReady) {
            return;
        }
        clientReady = true;
        QMetaObject::invokeMethod(q, &Clipboard::sendServerData, Qt::QueuedConnection);
    }

    std::unique_ptr<const QMimeData> serverData;
    std::unique_ptr<QMimeData> clientData;

    QQueue<PendingRequest> pendingRequests;
    std::optional<PendingRequest> inFlightRequest;
    std::unique_ptr<QMimeData> stagingData;
    bool stagedHasImage = false;
    bool stagedHasText = false;
    std::function<uint32_t(uint32_t)> formatDataRequestHook;

    template<typename>
    struct function_arg_trait;
    template<typename Argument>
    struct function_arg_trait<uint32_t (Private::*)(Argument)> {
        typedef Argument argument_t;
    };

    template<auto func>
    inline static UINT processInMainThread(Clipboard *clipboard, function_arg_trait<decltype(func)>::argument_t packet)
    {
        uint32_t channelState;
        QMetaObject::invokeMethod(
            clipboard,
            [clipboard](function_arg_trait<decltype(func)>::argument_t packet) {
                return ((*clipboard->d).*func)(packet);
            },
            Qt::BlockingQueuedConnection,
            qReturnArg(channelState),
            packet);
        return channelState;
    }

    static UINT clientCapabilities(CliprdrServerContext *context, const CLIPRDR_CAPABILITIES *capabilities)
    {
        return processInMainThread<&Private::onClientCapabilities>(reinterpret_cast<Clipboard *>(context->custom), capabilities);
    }

    static UINT clientFormatList(CliprdrServerContext *context, const CLIPRDR_FORMAT_LIST *formatList)
    {
        return processInMainThread<&Private::onClientFormatList>(reinterpret_cast<Clipboard *>(context->custom), formatList);
    }

    static UINT clientFormatListResponse(CliprdrServerContext *context, const CLIPRDR_FORMAT_LIST_RESPONSE *formatListResponse)
    {
        return processInMainThread<&Private::onClientFormatListResponse>(reinterpret_cast<Clipboard *>(context->custom), formatListResponse);
    }

    static UINT clientFormatDataRequest(CliprdrServerContext *context, const CLIPRDR_FORMAT_DATA_REQUEST *formatDataRequest)
    {
        return processInMainThread<&Private::onClientFormatDataRequest>(reinterpret_cast<Clipboard *>(context->custom), formatDataRequest);
    }

    static UINT clientFormatDataResponse(CliprdrServerContext *context, const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse)
    {
        return processInMainThread<&Private::onClientFormatDataResponse>(reinterpret_cast<Clipboard *>(context->custom), formatDataResponse);
    }
};

QImage Clipboard::decodeImageSafely(const QByteArray &data, const char *format)
{
    if (data.isEmpty() || data.size() > MaxClipboardPayloadBytes) {
        return {};
    }

    QBuffer buffer;
    buffer.setData(data);
    if (!buffer.open(QIODevice::ReadOnly)) {
        return {};
    }

    QImageReader reader(&buffer, format);
    reader.setAutoTransform(false);
    // Inspect header dimensions BEFORE allocating pixel memory to neutralize decompression bombs.
    const QSize declaredSize = reader.size();
    if (!declaredSize.isValid() || !isSafeImageDimensions(declaredSize.width(), declaredSize.height())) {
        qCWarning(KRDP) << "Rejecting clipboard image with unsafe or oversized declared dimensions:" << declaredSize << "format=" << (format ? format : "");
        return {};
    }

    QImage img = reader.read();
    if (img.isNull() || !isSafeImageDimensions(img.width(), img.height()) || static_cast<uint64_t>(img.sizeInBytes()) > MaxDecodedImageBytes) {
        return {};
    }
    return img;
}

QByteArray Clipboard::encodeImageToPng(const QImage &image)
{
    if (image.isNull() || !isSafeImageDimensions(image.width(), image.height())) {
        return {};
    }
    QByteArray out;
    QBuffer buffer(&out);
    if (!buffer.open(QIODevice::WriteOnly)) {
        return {};
    }
    if (!image.save(&buffer, "PNG")) {
        return {};
    }
    if (out.size() > MaxClipboardPayloadBytes) {
        return {};
    }
    return out;
}

QByteArray Clipboard::encodeImageToDib(const QImage &image)
{
    if (image.isNull() || !isSafeImageDimensions(image.width(), image.height())) {
        return {};
    }

    // Many Windows GDI applications ignore alpha or render transparent pixels as black
    // when consuming CF_DIB; flatten alpha onto white for CF_DIB while "PNG" keeps full alpha.
    QImage opaque;
    if (image.hasAlphaChannel()) {
        opaque = QImage(image.size(), QImage::Format_RGB32);
        opaque.fill(Qt::white);
        QPainter painter(&opaque);
        painter.drawImage(0, 0, image);
    } else {
        opaque = image.convertToFormat(QImage::Format_RGB32);
    }

    QByteArray bmp;
    QBuffer buffer(&bmp);
    if (!buffer.open(QIODevice::WriteOnly)) {
        return {};
    }
    if (!opaque.save(&buffer, "BMP")) {
        return {};
    }
    // Strip the 14-byte BITMAPFILEHEADER ("BM"...) to produce a standard Win32 CF_DIB payload.
    if (bmp.size() <= 14 || bmp[0] != 'B' || bmp[1] != 'M') {
        return {};
    }
    QByteArray dib = bmp.mid(14);
    if (dib.size() > MaxClipboardPayloadBytes) {
        return {};
    }
    return dib;
}

QImage Clipboard::decodeDibToImage(const QByteArray &dibData)
{
    if (dibData.size() < 12 || dibData.size() > MaxClipboardPayloadBytes) {
        return {};
    }

    const uint32_t headerSize = readU32LE(dibData, 0);
    if (headerSize < 12 || static_cast<qsizetype>(headerSize) > dibData.size()) {
        return {};
    }

    uint32_t paletteBytes = 0;
    int declaredWidth = 0;
    int declaredHeight = 0;
    bool topDown = false;
    uint16_t bitCount = 0;
    uint32_t compression = 0;

    if (headerSize == 12) {
        // BITMAPCOREHEADER
        declaredWidth = static_cast<int>(readU16LE(dibData, 4));
        declaredHeight = static_cast<int>(readU16LE(dibData, 6));
        bitCount = readU16LE(dibData, 10);
        if (bitCount > 0 && bitCount <= 8) {
            paletteBytes = (1u << bitCount) * 3u;
        }
    } else if (headerSize >= 40) {
        // BITMAPINFOHEADER / BITMAPV4HEADER / BITMAPV5HEADER
        const int32_t rawW = static_cast<int32_t>(readU32LE(dibData, 4));
        const int32_t rawH = static_cast<int32_t>(readU32LE(dibData, 8));
        if (rawW <= 0 || rawH == 0 || rawH == std::numeric_limits<int32_t>::min()) {
            return {};
        }
        declaredWidth = rawW;
        declaredHeight = rawH < 0 ? -rawH : rawH;
        topDown = rawH < 0;
        bitCount = readU16LE(dibData, 14);
        compression = readU32LE(dibData, 16);
        const uint32_t clrUsed = readU32LE(dibData, 32);
        if (clrUsed > 0) {
            if (clrUsed > 65536u) {
                return {};
            }
            paletteBytes = clrUsed * 4u;
        } else if (bitCount > 0 && bitCount <= 8) {
            paletteBytes = (1u << bitCount) * 4u;
        }
        // For plain BITMAPINFOHEADER (40 bytes) with BI_BITFIELDS (3), 3 DWORD masks follow the header.
        if (headerSize == 40 && compression == 3u) {
            paletteBytes += 12u;
        }
    } else {
        return {};
    }

    // Enforce decoded pixel memory ceiling BEFORE synthesizing BMP or calling QImageReader (blocks RLE bombs).
    if (!isSafeImageDimensions(declaredWidth, declaredHeight)) {
        return {};
    }

    const uint64_t offBits = 14ull + uint64_t(headerSize) + uint64_t(paletteBytes);
    const uint64_t fileSize = 14ull + uint64_t(dibData.size());
    if (offBits > fileSize || fileSize > 0xFFFFFFFFull) {
        return {};
    }

    QByteArray bmp;
    bmp.resize(static_cast<qsizetype>(fileSize));
    bmp[0] = 'B';
    bmp[1] = 'M';
    writeU32LE(bmp.data() + 2, static_cast<uint32_t>(fileSize));
    writeU16LE(bmp.data() + 6, 0);
    writeU16LE(bmp.data() + 8, 0);
    writeU32LE(bmp.data() + 10, static_cast<uint32_t>(offBits));
    std::memcpy(bmp.data() + 14, dibData.constData(), static_cast<size_t>(dibData.size()));

    QImage image = decodeImageSafely(bmp, "BMP");
    if (!image.isNull()) {
        return image;
    }

    // Fallback for uncommon BITMAPV5HEADER / BI_BITFIELDS 32-bit or 24-bit DIBs that QImage's BMP reader declines.
    if (headerSize >= 40 && (bitCount == 32 || bitCount == 24) && (compression == 0u || compression == 3u)) {
        const uint64_t pixelOffsetU64 = uint64_t(headerSize) + uint64_t(paletteBytes);
        const uint64_t srcStride = ((uint64_t(declaredWidth) * (bitCount / 8)) + 3ull) & ~3ull;
        const uint64_t totalPixelBytes = srcStride * uint64_t(declaredHeight);
        if (pixelOffsetU64 <= uint64_t(dibData.size()) && totalPixelBytes <= uint64_t(dibData.size()) - pixelOffsetU64) {
            QImage out(declaredWidth, declaredHeight, bitCount == 32 ? QImage::Format_ARGB32 : QImage::Format_RGB888);
            if (out.isNull() || static_cast<uint64_t>(out.sizeInBytes()) > MaxDecodedImageBytes) {
                return {};
            }
            const auto *srcBase = reinterpret_cast<const uint8_t *>(dibData.constData() + static_cast<qsizetype>(pixelOffsetU64));
            for (int y = 0; y < declaredHeight; ++y) {
                const int srcY = topDown ? y : (declaredHeight - 1 - y);
                const uint8_t *srcRow = srcBase + static_cast<qsizetype>(srcStride) * srcY;
                if (bitCount == 32) {
                    std::memcpy(out.scanLine(y), srcRow, static_cast<size_t>(declaredWidth) * 4);
                } else {
                    uint8_t *dstRow = out.scanLine(y);
                    for (int x = 0; x < declaredWidth; ++x) {
                        dstRow[x * 3 + 0] = srcRow[x * 3 + 2];
                        dstRow[x * 3 + 1] = srcRow[x * 3 + 1];
                        dstRow[x * 3 + 2] = srcRow[x * 3 + 0];
                    }
                }
            }
            return out;
        }
    }

    return {};
}

Clipboard::Clipboard(RdpConnection *session)
    : QObject(nullptr)
    , d(std::make_unique<Private>(this))
{
    d->session = session;
}

Clipboard::~Clipboard()
{
}

bool Clipboard::initialize()
{
    if (d->clipContext) {
        return true;
    }

    auto peerContext = reinterpret_cast<PeerContext *>(d->session->rdpPeer()->context);

    d->clipContext = Private::CliprdrServerContextPtr{cliprdr_server_context_new(peerContext->virtualChannelManager), cliprdr_server_context_free};
    if (!d->clipContext) {
        qCWarning(KRDP) << "Failed creating Clipboard context";
        return false;
    }

    d->clipContext->useLongFormatNames = TRUE;
    d->clipContext->streamFileClipEnabled = FALSE;
    d->clipContext->fileClipNoFilePaths = FALSE;
    d->clipContext->canLockClipData = FALSE;
    d->clipContext->hasHugeFileSupport = FALSE;

    d->clipContext->custom = this;
    d->clipContext->rdpcontext = d->session->rdpPeer()->context;

    d->clipContext->ClientCapabilities = Private::clientCapabilities;
    d->clipContext->ClientFormatList = Private::clientFormatList;
    d->clipContext->ClientFormatListResponse = Private::clientFormatListResponse;
    d->clipContext->ClientFormatDataRequest = Private::clientFormatDataRequest;
    d->clipContext->ClientFormatDataResponse = Private::clientFormatDataResponse;

    // returns 0 on success
    // https://pub.freerdp.com/api/server_2cliprdr__main_8c.html#ab4e8a28c6b4371c2a5f34e8716ab1e9e
    if (d->clipContext->Start(d->clipContext.get())) {
        qCWarning(KRDP) << "Could not start Clipboard context";
        return false;
    };

    d->enabled = true;
    // flush a copy made before the cliprdr channel finished coming up, so it isn't silently lost
    QMetaObject::invokeMethod(this, &Clipboard::sendServerData, Qt::QueuedConnection);

    return true;
}

bool Clipboard::enabled()
{
    return d->enabled;
}

void Clipboard::close()
{
    d->pendingRequests.clear();
    d->inFlightRequest.reset();
    d->stagingData.reset();
    d->stagedHasImage = false;
    d->stagedHasText = false;
    d->clientReady = false;

    if (!d->clipContext) {
        return;
    }

    if (d->clipContext->Stop(d->clipContext.get())) {
        qCWarning(KRDP) << "Could not stop Clipboard context";
        return;
    };
    d->enabled = false;
}

void Clipboard::setServerData(const QMimeData *data)
{
    d->serverData.reset(data);
    QMetaObject::invokeMethod(this, &Clipboard::sendServerData, Qt::QueuedConnection);
}

std::unique_ptr<QMimeData> Clipboard::getClipboard() const
{
    return std::move(d->clientData);
}

void Clipboard::setFormatDataRequestHook(std::function<uint32_t(uint32_t)> hook)
{
    d->formatDataRequestHook = std::move(hook);
    d->enabled = true;
    d->clientReady = true;
}

uint32_t Clipboard::dispatchClientFormatList(const CLIPRDR_FORMAT_LIST *formatList)
{
    return d->onClientFormatList(formatList);
}

uint32_t Clipboard::dispatchClientFormatDataResponse(const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse)
{
    return d->onClientFormatDataResponse(formatDataResponse);
}

void Clipboard::sendServerData()
{
    if (!d->serverData || !d->enabled || !d->clipContext) {
        return;
    }
    // held until the client's init handshake completes; flushed from markClientReady()
    if (!d->clientReady) {
        return;
    }

    static char pngFormatName[] = "PNG";

    const bool hasText = d->serverData->hasText() && !d->serverData->text().isEmpty();
    const bool hasImage = d->serverData->hasImage() || d->serverData->hasFormat(u"image/png"_s);

    std::vector<CLIPRDR_FORMAT> formats;
    formats.reserve(3);
    if (hasText) {
        CLIPRDR_FORMAT fmt = {};
        fmt.formatId = CfUnicodeTextId;
        fmt.formatName = nullptr;
        formats.push_back(fmt);
    }
    if (hasImage) {
        CLIPRDR_FORMAT pngFmt = {};
        pngFmt.formatId = CustomPngFormatId;
        pngFmt.formatName = pngFormatName;
        formats.push_back(pngFmt);

        CLIPRDR_FORMAT dibFmt = {};
        dibFmt.formatId = CfDibId;
        dibFmt.formatName = nullptr;
        formats.push_back(dibFmt);
    }

    CLIPRDR_FORMAT_LIST formatList = {};
    formatList.common.msgType = CB_FORMAT_LIST;
    formatList.common.msgFlags = 0;
    formatList.numFormats = static_cast<UINT32>(formats.size());
    formatList.formats = formats.empty() ? nullptr : formats.data();
    d->clipContext->ServerFormatList(d->clipContext.get(), &formatList);
}

void Clipboard::Private::requestNextPendingFormat()
{
    if ((!clipContext && !formatDataRequestHook) || !enabled) {
        pendingRequests.clear();
        inFlightRequest.reset();
        return;
    }

    // Keep strictly one CB_FORMAT_DATA_REQUEST in flight on the wire so untagged
    // CB_FORMAT_DATA_RESPONSE PDUs can never be misattributed across overlapping format lists.
    if (inFlightRequest.has_value()) {
        return;
    }

    while (!pendingRequests.isEmpty()) {
        const PendingRequest next = pendingRequests.dequeue();
        if (next.isImageFallback && stagedHasImage) {
            continue;
        }
        inFlightRequest = next;

        UINT rc = CHANNEL_RC_OK;
        if (formatDataRequestHook) {
            rc = formatDataRequestHook(next.formatId);
        } else {
            CLIPRDR_FORMAT_DATA_REQUEST formatDataRequest{
                .common = CLIPRDR_HEADER({.msgType = CB_FORMAT_DATA_REQUEST, .msgFlags = 0, .dataLen = 4}),
                .requestedFormatId = next.formatId,
            };
            rc = clipContext->ServerFormatDataRequest(clipContext.get(), &formatDataRequest);
        }
        if (rc != CHANNEL_RC_OK) {
            qCWarning(KRDP) << "Clipboard ServerFormatDataRequest failed for format" << next.formatId << "rc=" << rc;
            inFlightRequest.reset();
            continue;
        }
        return;
    }

    finalizeStagedClientData();
}

void Clipboard::Private::finalizeStagedClientData()
{
    if (stagingData && (stagedHasText || stagedHasImage)) {
        clientData = std::move(stagingData);
    } else {
        stagingData.reset();
        clientData.reset();
    }
    stagedHasImage = false;
    stagedHasText = false;
    Q_EMIT q->clientDataChanged();
}

uint32_t Clipboard::Private::onClientCapabilities(const CLIPRDR_CAPABILITIES *)
{
    // covers copy-out with no prior copy-in: mstsc sends no format list when its clipboard starts empty
    markClientReady();
    return CHANNEL_RC_OK;
}

uint32_t Clipboard::Private::onClientFormatList(const CLIPRDR_FORMAT_LIST *formatList)
{
    // fallback readiness signal for clients that reach us with a format list first
    markClientReady();

    if (clipContext && clipContext->ServerFormatListResponse) {
        // Acknowledge the client's format list first (required by MS-RDPECLIP protocol)
        CLIPRDR_FORMAT_LIST_RESPONSE response = {};
        response.common.msgType = CB_FORMAT_LIST_RESPONSE;
        response.common.msgFlags = CB_RESPONSE_OK;
        clipContext->ServerFormatListResponse(clipContext.get(), &response);
    }

    std::optional<uint32_t> unicodeTextId;
    std::optional<uint32_t> ansiTextId;
    std::optional<uint32_t> pngId;
    std::optional<uint32_t> dibId;
    std::optional<uint32_t> dibV5Id;

    for (uint32_t i = 0; i < formatList->numFormats; ++i) {
        const auto &format = formatList->formats[i];
        if (isPngFormatName(format.formatName)) {
            pngId = format.formatId;
            continue;
        }
        switch (format.formatId) {
        case CfUnicodeTextId:
            unicodeTextId = CfUnicodeTextId;
            break;
        case CfTextId:
            ansiTextId = CfTextId;
            break;
        case CfDibId:
            dibId = CfDibId;
            break;
        case CfDibV5Id:
            dibV5Id = CfDibV5Id;
            break;
        default:
            break;
        }
    }

    // If a prior CB_FORMAT_DATA_REQUEST is still awaiting a response from the client,
    // mark it discarded rather than clearing it so its late response is cleanly dropped
    // before we issue requests for this newer format list.
    if (inFlightRequest.has_value()) {
        inFlightRequest->discarded = true;
    }

    pendingRequests.clear();
    stagingData = std::make_unique<QMimeData>();
    stagedHasImage = false;
    stagedHasText = false;

    bool haveImageCandidate = false;
    if (pngId) {
        pendingRequests.enqueue(PendingRequest{*pngId, FormatKind::ImagePng, false, false});
        haveImageCandidate = true;
    }
    if (dibId) {
        pendingRequests.enqueue(PendingRequest{*dibId, FormatKind::ImageDib, haveImageCandidate, false});
        haveImageCandidate = true;
    }
    if (dibV5Id) {
        pendingRequests.enqueue(PendingRequest{*dibV5Id, FormatKind::ImageDib, haveImageCandidate, false});
        haveImageCandidate = true;
    }

    if (unicodeTextId) {
        pendingRequests.enqueue(PendingRequest{*unicodeTextId, FormatKind::UnicodeText, false, false});
    } else if (ansiTextId) {
        pendingRequests.enqueue(PendingRequest{*ansiTextId, FormatKind::AnsiText, false, false});
    }

    if (pendingRequests.isEmpty()) {
        stagingData.reset();
        return CHANNEL_RC_OK;
    }

    requestNextPendingFormat();
    return CHANNEL_RC_OK;
}

uint32_t Clipboard::Private::onClientFormatListResponse(const CLIPRDR_FORMAT_LIST_RESPONSE *formatListResponse)
{
    Q_UNUSED(formatListResponse);
    return CHANNEL_RC_OK;
}

uint32_t Clipboard::Private::onClientFormatDataRequest(const CLIPRDR_FORMAT_DATA_REQUEST *formatDataRequest)
{
    auto sendFail = [this]() {
        CLIPRDR_FORMAT_DATA_RESPONSE response = {};
        response.common.msgType = CB_FORMAT_DATA_RESPONSE;
        response.common.msgFlags = CB_RESPONSE_FAIL;
        response.common.dataLen = 0;
        response.requestedFormatData = nullptr;
        clipContext->ServerFormatDataResponse(clipContext.get(), &response);
        return CHANNEL_RC_OK;
    };

    if (!serverData) {
        return sendFail();
    }

    QByteArray payload;
    const uint32_t reqId = formatDataRequest->requestedFormatId;
    if (reqId == CfUnicodeTextId) {
        if (!serverData->hasText()) {
            return sendFail();
        }
        const QString text = serverData->text();
        // CF_UNICODETEXT requires null-terminated UTF-16LE
        payload = QByteArray(reinterpret_cast<const char *>(text.utf16()), (text.length() + 1) * 2);
    } else if (reqId == CustomPngFormatId) {
        if (serverData->hasFormat(u"image/png"_s)) {
            const QByteArray raw = serverData->data(u"image/png"_s);
            if (!Clipboard::decodeImageSafely(raw, "PNG").isNull()) {
                payload = raw;
            }
        }
        if (payload.isEmpty()) {
            const QImage img = extractServerImage(serverData.get());
            payload = Clipboard::encodeImageToPng(img);
        }
        if (payload.isEmpty() || payload.size() > MaxClipboardPayloadBytes) {
            return sendFail();
        }
    } else if (reqId == CfDibId) {
        const QImage img = extractServerImage(serverData.get());
        payload = Clipboard::encodeImageToDib(img);
        if (payload.isEmpty()) {
            return sendFail();
        }
    } else {
        return sendFail();
    }

    CLIPRDR_FORMAT_DATA_RESPONSE response = {};
    response.common.msgType = CB_FORMAT_DATA_RESPONSE;
    response.common.msgFlags = CB_RESPONSE_OK;
    response.common.dataLen = static_cast<UINT32>(payload.size());
    response.requestedFormatData = reinterpret_cast<const BYTE *>(payload.constData());

    clipContext->ServerFormatDataResponse(clipContext.get(), &response);

    return CHANNEL_RC_OK;
}

uint32_t Clipboard::Private::onClientFormatDataResponse(const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse)
{
    if (!inFlightRequest) {
        return CHANNEL_RC_OK;
    }
    const PendingRequest completed = *inFlightRequest;
    inFlightRequest.reset();

    if (completed.discarded) {
        requestNextPendingFormat();
        return CHANNEL_RC_OK;
    }

    if ((formatDataResponse->common.msgFlags & CB_RESPONSE_OK) && formatDataResponse->requestedFormatData && formatDataResponse->common.dataLen > 0
        && static_cast<qsizetype>(formatDataResponse->common.dataLen) <= MaxClipboardPayloadBytes && stagingData) {
        const auto *rawBytes = reinterpret_cast<const char *>(formatDataResponse->requestedFormatData);
        const qsizetype rawLen = static_cast<qsizetype>(formatDataResponse->common.dataLen);

        switch (completed.kind) {
        case FormatKind::UnicodeText: {
            if (rawLen >= 2) {
                qsizetype nChars = rawLen / 2;
                const auto *u16 = reinterpret_cast<const char16_t *>(rawBytes);
                while (nChars > 0 && u16[nChars - 1] == u'\0') {
                    --nChars;
                }
                stagingData->setText(QString::fromUtf16(u16, nChars));
                stagedHasText = true;
            }
            break;
        }
        case FormatKind::AnsiText: {
            qsizetype len = rawLen;
            while (len > 0 && rawBytes[len - 1] == '\0') {
                --len;
            }
            stagingData->setText(QString::fromLatin1(rawBytes, len));
            stagedHasText = true;
            break;
        }
        case FormatKind::ImagePng: {
            const QByteArray png(rawBytes, rawLen);
            const QImage img = Clipboard::decodeImageSafely(png, "PNG");
            if (!img.isNull()) {
                stagingData->setImageData(img);
                stagingData->setData(u"image/png"_s, png);
                stagedHasImage = true;
                qCDebug(KRDP) << "Clipboard received PNG image from client:" << img.size() << "(" << png.size() << "bytes)";
            }
            break;
        }
        case FormatKind::ImageDib: {
            const QByteArray dib(rawBytes, rawLen);
            const QImage img = Clipboard::decodeDibToImage(dib);
            if (!img.isNull()) {
                stagingData->setImageData(img);
                const QByteArray png = Clipboard::encodeImageToPng(img);
                if (!png.isEmpty()) {
                    stagingData->setData(u"image/png"_s, png);
                }
                stagedHasImage = true;
                qCDebug(KRDP) << "Clipboard received DIB image from client:" << img.size() << "(" << dib.size() << "bytes)";
            } else {
                qCWarning(KRDP) << "Clipboard failed to decode DIB image payload of" << dib.size() << "bytes";
            }
            break;
        }
        }
    }

    requestNextPendingFormat();
    return CHANNEL_RC_OK;
}
}
