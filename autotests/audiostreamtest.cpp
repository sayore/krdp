// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <QProcess>
#include <QTemporaryDir>
#include <QTest>

#include <array>
#include <atomic>
#include <filesystem>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "AudioStream.h"
#include "RdpConnection.h"
#include "Server.h"

namespace
{
AUDIO_FORMAT makeFmt(uint16_t tag, uint16_t ch, uint32_t rate, uint16_t bits)
{
    AUDIO_FORMAT f = {};
    f.wFormatTag = tag;
    f.nChannels = ch;
    f.nSamplesPerSec = rate;
    f.wBitsPerSample = bits;
    f.nBlockAlign = static_cast<uint16_t>(ch * (bits / 8));
    f.nAvgBytesPerSec = rate * f.nBlockAlign;
    return f;
}
} // namespace

class AudioStreamTest : public QObject
{
    Q_OBJECT

private:
    QTemporaryDir m_tempDir;
    std::filesystem::path m_certPath;
    std::filesystem::path m_keyPath;

private Q_SLOTS:
    void initTestCase()
    {
        QVERIFY(m_tempDir.isValid());
        m_certPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.crt")).toStdString());
        m_keyPath = std::filesystem::path(m_tempDir.filePath(QStringLiteral("server.key")).toStdString());

        QProcess openssl;
        openssl.start(QStringLiteral("openssl"),
                      {QStringLiteral("req"),
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
                       QStringLiteral("/CN=krdp-audio-test")});
        QVERIFY(openssl.waitForFinished(15000));
        QCOMPARE(openssl.exitCode(), 0);
    }

    void testSelectBestClientFormat()
    {
        // Prefers 48kHz stereo 16-bit PCM over MP3, 44.1kHz stereo, and 48kHz mono
        const std::array<AUDIO_FORMAT, 4> formats = {
            makeFmt(WAVE_FORMAT_MPEGLAYER3, 2, 48000, 16),
            makeFmt(WAVE_FORMAT_PCM, 2, 44100, 16),
            makeFmt(WAVE_FORMAT_PCM, 1, 48000, 16),
            makeFmt(WAVE_FORMAT_PCM, 2, 48000, 16),
        };
        const auto best = KRdp::AudioStream::selectBestClientFormat(formats.data(), static_cast<uint16_t>(formats.size()));
        QVERIFY(best.has_value());
        QCOMPARE(*best, uint16_t(3));

        // Falls back to 44.1kHz stereo when 48kHz stereo is absent
        const std::array<AUDIO_FORMAT, 2> fallback = {
            makeFmt(WAVE_FORMAT_PCM, 1, 48000, 16),
            makeFmt(WAVE_FORMAT_PCM, 2, 44100, 16),
        };
        const auto bestFallback = KRdp::AudioStream::selectBestClientFormat(fallback.data(), static_cast<uint16_t>(fallback.size()));
        QVERIFY(bestFallback.has_value());
        QCOMPARE(*bestFallback, uint16_t(1));

        // Rejects non-PCM / 8-bit / null / empty format lists
        const std::array<AUDIO_FORMAT, 2> incompatible = {
            makeFmt(WAVE_FORMAT_ADPCM, 2, 44100, 4),
            makeFmt(WAVE_FORMAT_PCM, 2, 44100, 8),
        };
        QVERIFY(!KRdp::AudioStream::selectBestClientFormat(incompatible.data(), static_cast<uint16_t>(incompatible.size())).has_value());
        QVERIFY(!KRdp::AudioStream::selectBestClientFormat(nullptr, 0).has_value());
    }

    void testSilenceDetection()
    {
        const std::array<int16_t, 8> silent = {0, 1, -1, 0, 1, -1, 0, 0};
        QVERIFY(!KRdp::AudioStream::isChunkAudible(silent.data(), silent.size()));

        const std::array<int16_t, 8> quietSignal = {0, 0, 0, 2, 0, 0, 0, 0};
        QVERIFY(KRdp::AudioStream::isChunkAudible(quietSignal.data(), quietSignal.size()));

        const std::array<int16_t, 4> negSignal = {0, -512, 0, 0};
        QVERIFY(KRdp::AudioStream::isChunkAudible(negSignal.data(), negSignal.size()));

        QVERIFY(!KRdp::AudioStream::isChunkAudible(nullptr, 0));
    }

    void testPcmRingBufferBoundedOverflowAndThreadSafety()
    {
        // 1. Bounded overflow / backpressure check
        KRdp::AudioStream::PcmRingBuffer ring;
        ring.configure(1024);
        QCOMPARE(ring.capacity(), size_t(1024));

        std::vector<int16_t> block(1500);
        for (size_t i = 0; i < block.size(); ++i) {
            block[i] = static_cast<int16_t>(i & 0x7FFF);
        }
        const size_t written = ring.write(block.data(), block.size());
        QCOMPARE(written, size_t(1024));
        QCOMPARE(ring.available(), size_t(1024));
        QCOMPARE(ring.droppedSamples(), uint64_t(476));

        std::vector<int16_t> out(1024);
        QCOMPARE(ring.read(out.data(), out.size()), size_t(1024));
        for (size_t i = 0; i < out.size(); ++i) {
            QCOMPARE(out[i], static_cast<int16_t>(i & 0x7FFF));
        }

        // 2. Concurrent SPSC lock-free thread-safety stress test (100,000 samples across 2 threads)
        ring.configure(4096);
        constexpr size_t TotalSamples = 100'000;
        std::atomic<bool> producerDone{false};
        std::atomic<bool> sequenceMismatch{false};
        std::atomic<size_t> totalConsumed{0};

        std::thread producer([&]() {
            std::array<int16_t, 128> chunk{};
            size_t sent = 0;
            while (sent < TotalSamples) {
                const size_t batch = std::min(chunk.size(), TotalSamples - sent);
                for (size_t i = 0; i < batch; ++i) {
                    chunk[i] = static_cast<int16_t>((sent + i) % 30000);
                }
                size_t off = 0;
                while (off < batch) {
                    const size_t w = ring.write(chunk.data() + off, batch - off);
                    off += w;
                    if (w == 0) {
                        std::this_thread::yield();
                    }
                }
                sent += batch;
            }
            producerDone.store(true, std::memory_order_release);
        });

        std::thread consumer([&]() {
            std::array<int16_t, 96> chunk{};
            size_t expectedIdx = 0;
            while (!producerDone.load(std::memory_order_acquire) || ring.available() > 0) {
                const size_t got = ring.read(chunk.data(), chunk.size());
                for (size_t i = 0; i < got; ++i) {
                    if (chunk[i] != static_cast<int16_t>((expectedIdx + i) % 30000)) {
                        sequenceMismatch.store(true, std::memory_order_release);
                    }
                }
                expectedIdx += got;
                if (got == 0) {
                    std::this_thread::yield();
                }
            }
            totalConsumed.store(expectedIdx, std::memory_order_release);
        });

        producer.join();
        consumer.join();

        QVERIFY(!sequenceMismatch.load());
        QCOMPARE(totalConsumed.load(), TotalSamples);
    }

    void testStrictPreAuthIsolation()
    {
        KRdp::Server server;
        server.setTransport(KRdp::Server::Transport::Tcp);
        server.setAddress(QHostAddress::LocalHost);
        server.setPort(0);
        server.setUsePAMAuthentication(true);
        server.setTlsCertificate(m_certPath);
        server.setTlsCertificateKey(m_keyPath);
        QVERIFY(server.start());

        int fds[2] = {-1, -1};
        QCOMPARE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
        KRdp::RdpConnection conn(&server, fds[0]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Running, 2000);
        QVERIFY(!conn.isAuthenticated());

        QVERIFY(!conn.audioStream()->initialize(true));
        QVERIFY(!conn.audioStream()->initialize(false));
        QVERIFY(!conn.audioStream()->enabled());
        QVERIFY(!conn.audioStream()->activated());

        conn.close();
        ::close(fds[1]);
        QTRY_COMPARE_WITH_TIMEOUT(conn.state(), KRdp::RdpConnection::State::Closed, 2000);
        server.stop();
    }
};

QTEST_MAIN(AudioStreamTest)
#include "audiostreamtest.moc"
