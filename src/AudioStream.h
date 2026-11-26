// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <QObject>

#include <freerdp/codec/audio.h>

#include "krdp_export.h"

namespace KRdp
{

class RdpConnection;

/**
 * Encapsulates an MS-RDPEA (RDPSND) audio output stream backed by a native PipeWire virtual Audio/Sink.
 *
 * Exposes a virtual PipeWire Audio/Sink ("Remote Audio (RDP)") visible in KDE Plasma's
 * volume control without requiring PulseAudio client libraries, and streams 16-bit PCM
 * frames directly via SNDC_WAVE2 (SendSamples2) over AUDIO_PLAYBACK_DVC (preferred)
 * or the static "rdpsnd" virtual channel.
 *
 * Strictly gated on RdpConnection::isAuthenticated() — never initialized while
 * the connection is in Unauthenticated or PendingInBandGreeter state.
 */
class KRDP_EXPORT AudioStream : public QObject
{
    Q_OBJECT

public:
    /**
     * Lock-free, fixed-capacity Single-Producer Single-Consumer ring buffer for
     * real-time PipeWire audio callbacks (zero allocations, zero mutexes on RT path).
     */
    class KRDP_EXPORT PcmRingBuffer
    {
    public:
        void configure(size_t minCapacitySamples);
        void reset();

        size_t capacity() const;
        size_t available() const;
        uint64_t droppedSamples() const;

        // Real-time producer thread only: wait-free, allocation-free.
        size_t write(const int16_t *src, size_t count);
        // Consumer TX thread only: wait-free, allocation-free.
        size_t read(int16_t *dst, size_t count);
        size_t discard(size_t count);

    private:
        std::vector<int16_t> m_storage;
        size_t m_capacity = 0;
        size_t m_mask = 0;
        alignas(64) std::atomic<size_t> m_writePos{0};
        alignas(64) std::atomic<size_t> m_readPos{0};
        std::atomic<uint64_t> m_droppedSamples{0};
    };

    explicit AudioStream(RdpConnection *session);
    ~AudioStream() override;

    bool initialize(bool useDynamicChannel);
    void close();

    bool enabled() const;
    bool activated() const;

    static std::optional<uint16_t> selectBestClientFormat(const AUDIO_FORMAT *formats, uint16_t count);
    static bool isChunkAudible(const int16_t *samples, size_t sampleCount);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

} // namespace KRdp
