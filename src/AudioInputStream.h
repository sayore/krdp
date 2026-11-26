// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include <QObject>

#include <freerdp/codec/audio.h>

#include "krdp_export.h"

namespace KRdp
{

class RdpConnection;

/**
 * Encapsulates an MS-RDPEAI (AUDIN) audio input (microphone) stream backed by a
 * native PipeWire virtual Audio/Source ("Remote Microphone (RDP)").
 *
 * Strictly gated on RdpConnection::isAuthenticated() — never initialized while
 * the connection is in Unauthenticated or PendingInBandGreeter state.
 *
 * Demand-driven privacy: only sends SNDIN_OPEN to start host microphone recording
 * while a guest application is actively streaming from the PipeWire Audio/Source,
 * and closes the AUDIO_INPUT channel when recording stops.
 */
class KRDP_EXPORT AudioInputStream : public QObject
{
    Q_OBJECT

public:
    explicit AudioInputStream(RdpConnection *session);
    ~AudioInputStream() override;

    bool initialize();
    void close();

    bool enabled() const;
    bool capturing() const;

    static std::optional<uint32_t> selectBestClientFormat(const AUDIO_FORMAT *formats, uint32_t count);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace KRdp
