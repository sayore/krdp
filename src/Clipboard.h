// SPDX-FileCopyrightText: 2024 Akseli Lahtinen <akselmo@akselmo.dev>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <QByteArray>
#include <QImage>
#include <QMimeData>
#include <QObject>

#include <freerdp/freerdp.h>
#include <freerdp/server/cliprdr.h>

#include <functional>
#include <mutex>

#include "krdp_export.h"

class ClipboardImageTest;

namespace KRdp
{

class RdpConnection;

class KRDP_EXPORT Clipboard : public QObject
{
    Q_OBJECT

public:
    explicit Clipboard(RdpConnection *session);
    ~Clipboard() override;

    bool initialize();
    void close();

    bool enabled();

    void setServerData(const QMimeData *data);

    Q_SIGNAL void clientDataChanged();
    std::unique_ptr<QMimeData> getClipboard() const;

    static QByteArray encodeImageToDib(const QImage &image);
    static QImage decodeDibToImage(const QByteArray &dibData);
    static QByteArray encodeImageToPng(const QImage &image);
    static QImage decodeImageSafely(const QByteArray &data, const char *format);

private:
    friend class ::ClipboardImageTest;
    void sendServerData();
    void setFormatDataRequestHook(std::function<uint32_t(uint32_t)> hook);
    uint32_t dispatchClientFormatList(const CLIPRDR_FORMAT_LIST *formatList);
    uint32_t dispatchClientFormatDataResponse(const CLIPRDR_FORMAT_DATA_RESPONSE *formatDataResponse);

    class Private;
    const std::unique_ptr<Private> d;
};
}
