// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QByteArray>
#include <QColor>
#include <QImage>
#include <QSignalSpy>
#include <QTest>

#include <cstdint>
#include <limits>
#include <vector>

#include "Clipboard.h"

namespace
{
void putU16LE(QByteArray &buf, int off, uint16_t v)
{
    buf[off] = static_cast<char>(v & 0xFFu);
    buf[off + 1] = static_cast<char>((v >> 8) & 0xFFu);
}

void putU32LE(QByteArray &buf, int off, uint32_t v)
{
    buf[off] = static_cast<char>(v & 0xFFu);
    buf[off + 1] = static_cast<char>((v >> 8) & 0xFFu);
    buf[off + 2] = static_cast<char>((v >> 16) & 0xFFu);
    buf[off + 3] = static_cast<char>((v >> 24) & 0xFFu);
}
} // namespace

class ClipboardImageTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void testOpaqueDibRoundtrip()
    {
        QImage src(16, 12, QImage::Format_RGB32);
        src.fill(QColor(0x12, 0x34, 0x56));
        src.setPixelColor(0, 0, QColor(0xFF, 0x00, 0x00));
        src.setPixelColor(15, 11, QColor(0x00, 0xFF, 0x80));

        const QByteArray dib = KRdp::Clipboard::encodeImageToDib(src);
        QVERIFY(dib.size() > 40);
        QVERIFY(!(dib[0] == 'B' && dib[1] == 'M')); // BITMAPFILEHEADER must be stripped

        const QImage decoded = KRdp::Clipboard::decodeDibToImage(dib);
        QVERIFY(!decoded.isNull());
        QCOMPARE(decoded.size(), src.size());
        QCOMPARE(decoded.pixelColor(0, 0).rgb(), QColor(0xFF, 0x00, 0x00).rgb());
        QCOMPARE(decoded.pixelColor(15, 11).rgb(), QColor(0x00, 0xFF, 0x80).rgb());
        QCOMPARE(decoded.pixelColor(5, 5).rgb(), QColor(0x12, 0x34, 0x56).rgb());
    }

    void testAlphaPngPreservedAndDibFlattened()
    {
        QImage alphaImg(8, 8, QImage::Format_ARGB32);
        alphaImg.fill(QColor(0, 0, 0, 0));
        alphaImg.setPixelColor(2, 2, QColor(0x10, 0x20, 0x30, 0xFF));

        const QByteArray png = KRdp::Clipboard::encodeImageToPng(alphaImg);
        QVERIFY(png.startsWith("\x89PNG"));
        QImage decodedPng;
        QVERIFY(decodedPng.loadFromData(png, "PNG"));
        QCOMPARE(decodedPng.pixelColor(0, 0).alpha(), 0);
        QCOMPARE(decodedPng.pixelColor(2, 2), QColor(0x10, 0x20, 0x30, 0xFF));

        const QByteArray dib = KRdp::Clipboard::encodeImageToDib(alphaImg);
        const QImage decodedDib = KRdp::Clipboard::decodeDibToImage(dib);
        QVERIFY(!decodedDib.isNull());
        QCOMPARE(decodedDib.pixelColor(0, 0).rgb(), QColor(0xFF, 0xFF, 0xFF).rgb());
        QCOMPARE(decodedDib.pixelColor(2, 2).rgb(), QColor(0x10, 0x20, 0x30).rgb());
    }

    void testDibV5TopDownDecode()
    {
        QByteArray dibV5(124 + 4 * 2 * 2, '\0');
        putU32LE(dibV5, 0, 124); // bV5Size
        putU32LE(dibV5, 4, 2); // width
        putU32LE(dibV5, 8, static_cast<uint32_t>(-2)); // top-down height = 2
        putU16LE(dibV5, 12, 1); // planes
        putU16LE(dibV5, 14, 32); // bitCount
        putU32LE(dibV5, 16, 0); // BI_RGB
        dibV5[124] = 0x11; // B
        dibV5[125] = 0x22; // G
        dibV5[126] = 0x33; // R
        dibV5[127] = static_cast<char>(0xFF); // A

        const QImage decoded = KRdp::Clipboard::decodeDibToImage(dibV5);
        QVERIFY(!decoded.isNull());
        QCOMPARE(decoded.size(), QSize(2, 2));
        QCOMPARE(decoded.pixelColor(0, 0).rgb(), QColor(0x33, 0x22, 0x11).rgb());
    }

    void testDibBitfields40ByteHeader()
    {
        // 40-byte BITMAPINFOHEADER + 12-byte BI_BITFIELDS masks + 2x2 32-bit pixels (bottom-up)
        QByteArray dib(40 + 12 + 4 * 2 * 2, '\0');
        putU32LE(dib, 0, 40);
        putU32LE(dib, 4, 2);
        putU32LE(dib, 8, 2);
        putU16LE(dib, 12, 1);
        putU16LE(dib, 14, 32);
        putU32LE(dib, 16, 3); // BI_BITFIELDS
        putU32LE(dib, 40, 0x00FF0000u); // R mask
        putU32LE(dib, 44, 0x0000FF00u); // G mask
        putU32LE(dib, 48, 0x000000FFu); // B mask
        // Bottom row (y = 1) starts at offset 52, top row (y = 0) at offset 60
        dib[60] = 0x44; // B
        dib[61] = 0x55; // G
        dib[62] = 0x66; // R
        dib[63] = static_cast<char>(0xFF);

        const QImage decoded = KRdp::Clipboard::decodeDibToImage(dib);
        QVERIFY(!decoded.isNull());
        QCOMPARE(decoded.size(), QSize(2, 2));
        QCOMPARE(decoded.pixelColor(0, 0).rgb(), QColor(0x66, 0x55, 0x44).rgb());
    }

    void testUntrustedMalformedDibPayloadsRejected()
    {
        QVERIFY(KRdp::Clipboard::decodeDibToImage(QByteArray()).isNull());
        QVERIFY(KRdp::Clipboard::decodeDibToImage(QByteArray(8, '\0')).isNull());

        // Header size larger than payload
        QByteArray badHdr(40, '\0');
        putU32LE(badHdr, 0, 9999);
        QVERIFY(KRdp::Clipboard::decodeDibToImage(badHdr).isNull());

        // INT32_MIN height overflow test
        QByteArray minHeight(64, '\0');
        putU32LE(minHeight, 0, 40);
        putU32LE(minHeight, 4, 2);
        putU32LE(minHeight, 8, static_cast<uint32_t>(std::numeric_limits<int32_t>::min()));
        putU16LE(minHeight, 12, 1);
        putU16LE(minHeight, 14, 32);
        QVERIFY(KRdp::Clipboard::decodeDibToImage(minHeight).isNull());

        // Excessive dimensions (> 16384)
        QByteArray hugeDim(64, '\0');
        putU32LE(hugeDim, 0, 40);
        putU32LE(hugeDim, 4, 30000);
        putU32LE(hugeDim, 8, 30000);
        putU16LE(hugeDim, 12, 1);
        putU16LE(hugeDim, 14, 32);
        QVERIFY(KRdp::Clipboard::decodeDibToImage(hugeDim).isNull());

        // Excessive clrUsed palette count
        QByteArray hugePalette(64, '\0');
        putU32LE(hugePalette, 0, 40);
        putU32LE(hugePalette, 4, 2);
        putU32LE(hugePalette, 8, 2);
        putU16LE(hugePalette, 12, 1);
        putU16LE(hugePalette, 14, 8);
        putU32LE(hugePalette, 32, 0x10000000u);
        QVERIFY(KRdp::Clipboard::decodeDibToImage(hugePalette).isNull());

        // DIB RLE decompression bomb (10000x10000 -> 400 MiB RGBA > 64 MiB decoded budget)
        QByteArray dibBomb(64, '\0');
        putU32LE(dibBomb, 0, 40);
        putU32LE(dibBomb, 4, 10000);
        putU32LE(dibBomb, 8, 10000);
        putU16LE(dibBomb, 12, 1);
        putU16LE(dibBomb, 14, 8);
        putU32LE(dibBomb, 16, 1); // BI_RLE8
        QVERIFY(KRdp::Clipboard::decodeDibToImage(dibBomb).isNull());
    }

    void testPngDecompressionBombRejectedBeforeDecode()
    {
        // Minimal valid PNG header declaring 16384x16384 RGBA (1 GiB uncompressed) in 33 bytes.
        // QImageReader::size() must reject this BEFORE allocating pixel memory.
        QByteArray bombPng = QByteArray::fromHex(
            "89504e470d0a1a0a" // PNG signature
            "0000000d" // IHDR length = 13
            "49484452" // "IHDR"
            "00004000" // width = 16384
            "00004000" // height = 16384
            "08" // bit depth = 8
            "06" // color type = RGBA
            "000000" // compression/filter/interlace
            "00000000" // CRC placeholder
            "0000000049454e44ae426082"); // IEND
        QVERIFY(KRdp::Clipboard::decodeImageSafely(bombPng, "PNG").isNull());
    }

    void testOverlappingFormatListsDiscardStaleResponse()
    {
        KRdp::Clipboard clipboard(nullptr);
        QSignalSpy changedSpy(&clipboard, &KRdp::Clipboard::clientDataChanged);
        std::vector<uint32_t> requestedFormatIds;
        clipboard.setFormatDataRequestHook([&](uint32_t fmtId) -> uint32_t {
            requestedFormatIds.push_back(fmtId);
            return CHANNEL_RC_OK;
        });

        // 1. Client sends FormatList #1 offering CF_UNICODETEXT (13)
        CLIPRDR_FORMAT fmtText = {};
        fmtText.formatId = 13;
        fmtText.formatName = nullptr;
        CLIPRDR_FORMAT_LIST list1 = {};
        list1.numFormats = 1;
        list1.formats = &fmtText;
        QCOMPARE(clipboard.dispatchClientFormatList(&list1), uint32_t(CHANNEL_RC_OK));
        QCOMPARE(requestedFormatIds.size(), size_t(1));
        QCOMPARE(requestedFormatIds[0], uint32_t(13));

        // 2. BEFORE response #1 arrives, client sends overlapping FormatList #2 offering PNG (0xC099)
        char pngName[] = "PNG";
        CLIPRDR_FORMAT fmtPng = {};
        fmtPng.formatId = 0xC099u;
        fmtPng.formatName = pngName;
        CLIPRDR_FORMAT_LIST list2 = {};
        list2.numFormats = 1;
        list2.formats = &fmtPng;
        QCOMPARE(clipboard.dispatchClientFormatList(&list2), uint32_t(CHANNEL_RC_OK));
        // Must NOT send a second concurrent wire request while response #1 is still in flight!
        QCOMPARE(requestedFormatIds.size(), size_t(1));

        // 3. Stale response #1 (UTF-16 text) arrives -> must be discarded, and now PNG request is sent!
        const QString staleText = QStringLiteral("stale");
        const QByteArray staleUtf16(reinterpret_cast<const char *>(staleText.utf16()), (staleText.size() + 1) * 2);
        CLIPRDR_FORMAT_DATA_RESPONSE resp1 = {};
        resp1.common.msgType = CB_FORMAT_DATA_RESPONSE;
        resp1.common.msgFlags = CB_RESPONSE_OK;
        resp1.common.dataLen = static_cast<UINT32>(staleUtf16.size());
        resp1.requestedFormatData = reinterpret_cast<const BYTE *>(staleUtf16.constData());
        QCOMPARE(clipboard.dispatchClientFormatDataResponse(&resp1), uint32_t(CHANNEL_RC_OK));
        QCOMPARE(changedSpy.count(), 0);
        QCOMPARE(requestedFormatIds.size(), size_t(2));
        QCOMPARE(requestedFormatIds[1], uint32_t(0xC099u));

        // 4. Response #2 (valid PNG image) arrives -> produces image cleanly without stale text!
        QImage expected(4, 4, QImage::Format_ARGB32);
        expected.fill(QColor(0x22, 0x44, 0x66, 0xFF));
        const QByteArray pngBytes = KRdp::Clipboard::encodeImageToPng(expected);
        QVERIFY(!pngBytes.isEmpty());

        CLIPRDR_FORMAT_DATA_RESPONSE resp2 = {};
        resp2.common.msgType = CB_FORMAT_DATA_RESPONSE;
        resp2.common.msgFlags = CB_RESPONSE_OK;
        resp2.common.dataLen = static_cast<UINT32>(pngBytes.size());
        resp2.requestedFormatData = reinterpret_cast<const BYTE *>(pngBytes.constData());
        QCOMPARE(clipboard.dispatchClientFormatDataResponse(&resp2), uint32_t(CHANNEL_RC_OK));

        QCOMPARE(changedSpy.count(), 1);
        const auto mime = clipboard.getClipboard();
        QVERIFY(mime != nullptr);
        QVERIFY(!mime->hasText());
        QVERIFY(mime->hasImage());
        const QImage got = qvariant_cast<QImage>(mime->imageData());
        QCOMPARE(got.size(), QSize(4, 4));
        QCOMPARE(got.pixelColor(1, 1).rgb(), QColor(0x22, 0x44, 0x66).rgb());
    }
};

QTEST_MAIN(ClipboardImageTest)
#include "clipboardimagetest.moc"
