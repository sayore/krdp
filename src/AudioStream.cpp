// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "AudioStream.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <freerdp/channels/rdpsnd.h>
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/server/rdpsnd.h>

#ifdef HAVE_PIPEWIRE_AUDIO
#include <pipewire/pipewire.h>
#include <spa/param/audio/format-utils.h>
#endif

#include "PeerContext_p.h"
#include "RdpConnection.h"
#include "krdp_logging.h"

namespace KRdp
{

namespace
{
size_t nextPowerOfTwo(size_t n)
{
    size_t p = 1;
    while (p < n && p < (size_t(1) << 24)) {
        p <<= 1;
    }
    return p;
}

constexpr AUDIO_FORMAT makePcmFormat(uint32_t sampleRate, uint16_t channels, uint16_t bitsPerSample = 16)
{
    const uint16_t blockAlign = static_cast<uint16_t>(channels * (bitsPerSample / 8));
    AUDIO_FORMAT fmt = {};
    fmt.wFormatTag = WAVE_FORMAT_PCM;
    fmt.nChannels = channels;
    fmt.nSamplesPerSec = sampleRate;
    fmt.nBlockAlign = blockAlign;
    fmt.nAvgBytesPerSec = sampleRate * blockAlign;
    fmt.wBitsPerSample = bitsPerSample;
    fmt.cbSize = 0;
    fmt.data = nullptr;
    return fmt;
}

int scorePcmFormat(const AUDIO_FORMAT &fmt)
{
    if (fmt.wFormatTag != WAVE_FORMAT_PCM || fmt.wBitsPerSample != 16) {
        return -1;
    }
    if (fmt.nChannels < 1 || fmt.nChannels > 2) {
        return -1;
    }
    if (fmt.nSamplesPerSec < 8000 || fmt.nSamplesPerSec > 48000) {
        return -1;
    }

    int score = 0;
    if (fmt.nChannels == 2) {
        score += 100;
    }
    // Prefer 44.1 kHz: Windows RDP clients (mstsc / Hyper-V VMConnect) advertise 48 kHz but were
    // measured to render RDPSND PCM at 44.1 kHz, which makes the client playout queue grow by ~8%
    // (~5 s per minute). 44.1 kHz is also what Windows RDP servers send by default.
    if (fmt.nSamplesPerSec == 44100) {
        score += 50;
    } else if (fmt.nSamplesPerSec == 48000) {
        score += 40;
    } else if (fmt.nSamplesPerSec == 32000) {
        score += 20;
    } else if (fmt.nSamplesPerSec == 22050) {
        score += 10;
    }
    return score;
}
} // namespace

void AudioStream::PcmRingBuffer::configure(size_t minCapacitySamples)
{
    const size_t cap = std::max<size_t>(1024, nextPowerOfTwo(minCapacitySamples));
    m_storage.assign(cap, 0);
    m_capacity = cap;
    m_mask = cap - 1;
    reset();
}

void AudioStream::PcmRingBuffer::reset()
{
    m_writePos.store(0, std::memory_order_relaxed);
    m_readPos.store(0, std::memory_order_relaxed);
    m_droppedSamples.store(0, std::memory_order_relaxed);
}

size_t AudioStream::PcmRingBuffer::capacity() const
{
    return m_capacity;
}

size_t AudioStream::PcmRingBuffer::available() const
{
    const size_t w = m_writePos.load(std::memory_order_acquire);
    const size_t r = m_readPos.load(std::memory_order_acquire);
    return w - r;
}

uint64_t AudioStream::PcmRingBuffer::droppedSamples() const
{
    return m_droppedSamples.load(std::memory_order_relaxed);
}

size_t AudioStream::PcmRingBuffer::write(const int16_t *src, size_t count)
{
    if (!src || count == 0 || m_capacity == 0) {
        return 0;
    }
    const size_t w = m_writePos.load(std::memory_order_relaxed);
    const size_t r = m_readPos.load(std::memory_order_acquire);
    const size_t freeSpace = m_capacity - (w - r);
    const size_t toWrite = std::min(count, freeSpace);
    if (toWrite < count) {
        m_droppedSamples.fetch_add(static_cast<uint64_t>(count - toWrite), std::memory_order_relaxed);
    }
    if (toWrite == 0) {
        return 0;
    }

    const size_t startIdx = w & m_mask;
    const size_t firstPart = std::min(toWrite, m_capacity - startIdx);
    std::memcpy(m_storage.data() + startIdx, src, firstPart * sizeof(int16_t));
    const size_t secondPart = toWrite - firstPart;
    if (secondPart > 0) {
        std::memcpy(m_storage.data(), src + firstPart, secondPart * sizeof(int16_t));
    }

    m_writePos.store(w + toWrite, std::memory_order_release);
    return toWrite;
}

size_t AudioStream::PcmRingBuffer::read(int16_t *dst, size_t count)
{
    if (!dst || count == 0 || m_capacity == 0) {
        return 0;
    }
    const size_t r = m_readPos.load(std::memory_order_relaxed);
    const size_t w = m_writePos.load(std::memory_order_acquire);
    const size_t avail = w - r;
    const size_t toRead = std::min(count, avail);
    if (toRead == 0) {
        return 0;
    }

    const size_t startIdx = r & m_mask;
    const size_t firstPart = std::min(toRead, m_capacity - startIdx);
    std::memcpy(dst, m_storage.data() + startIdx, firstPart * sizeof(int16_t));
    const size_t secondPart = toRead - firstPart;
    if (secondPart > 0) {
        std::memcpy(dst + firstPart, m_storage.data(), secondPart * sizeof(int16_t));
    }

    m_readPos.store(r + toRead, std::memory_order_release);
    return toRead;
}

size_t AudioStream::PcmRingBuffer::discard(size_t count)
{
    if (count == 0 || m_capacity == 0) {
        return 0;
    }
    const size_t r = m_readPos.load(std::memory_order_relaxed);
    const size_t w = m_writePos.load(std::memory_order_acquire);
    const size_t avail = w - r;
    const size_t toDiscard = std::min(count, avail);
    if (toDiscard > 0) {
        m_readPos.store(r + toDiscard, std::memory_order_release);
        m_droppedSamples.fetch_add(static_cast<uint64_t>(toDiscard), std::memory_order_relaxed);
    }
    return toDiscard;
}

class KRDP_NO_EXPORT AudioStream::Private
{
public:
    using RdpsndServerContextPtr = std::unique_ptr<RdpsndServerContext, decltype(&rdpsnd_server_context_free)>;

    explicit Private(AudioStream *qq)
        : q(qq)
    {
    }

    ~Private()
    {
        if (wakeEventFd >= 0) {
            ::close(wakeEventFd);
            wakeEventFd = -1;
        }
    }

    AudioStream *q = nullptr;
    RdpConnection *session = nullptr;

    std::mutex rdpsndMutex;
    RdpsndServerContextPtr rdpsndContext = RdpsndServerContextPtr(nullptr, rdpsnd_server_context_free);

    std::array<AUDIO_FORMAT, 4> serverFormats = {
        makePcmFormat(48000, 2, 16),
        makePcmFormat(44100, 2, 16),
        makePcmFormat(48000, 1, 16),
        makePcmFormat(44100, 1, 16),
    };
    AUDIO_FORMAT srcFormat = makePcmFormat(48000, 2, 16);

    std::atomic<bool> initialized{false};
    std::atomic<bool> enabled{false};
    std::atomic<bool> activated{false};
    std::atomic<bool> closing{false};
    std::atomic<uint16_t> selectedFormatIndex{0};
    std::atomic<int> inFlightBlocks{0};
    std::atomic<uint64_t> lastConfirmSteadyMs{0};

    // Client-side playout delay measurement (MS-RDPEA Wave Confirm echoes the wave timestamp
    // plus the client's render delay). Indexed by the 8-bit RDPSND block number.
    std::array<std::atomic<uint16_t>, 256> sentTimestamps{};
    std::atomic<int> clientDelayMs{-1}; // smoothed (EWMA), -1 = no sample yet
    std::atomic<int> clientDelayPeakMs{0};

    // Pre-allocated lock-free SPSC ring buffer between PipeWire RT thread and TX thread.
    std::mutex captureLifecycleMutex;
    size_t framesPerChunk = 960;
    size_t samplesPerChunk = 1920;
    AudioStream::PcmRingBuffer ringBuffer;
    int wakeEventFd = -1;
    std::jthread txThread;

    void signalWake() const
    {
        if (wakeEventFd >= 0) {
            const uint64_t one = 1;
            const ssize_t ignored = ::write(wakeEventFd, &one, sizeof(one));
            (void)ignored;
        }
    }

#ifdef HAVE_PIPEWIRE_AUDIO
    pw_thread_loop *pwLoop = nullptr;
    pw_stream *pwStream = nullptr;
    pw_stream_events pwStreamEvents = {};

    static void pwStateChangedCallback(void *userdata, enum pw_stream_state oldState, enum pw_stream_state state, const char *error);
    static void pwProcessCallback(void *userdata);
    bool startPipeWireCaptureLocked(uint32_t sampleRate, uint16_t channels);
    void stopPipeWireCaptureLocked();
#endif

    void onActivated(RdpsndServerContext *context);
    UINT onConfirmBlock(RdpsndServerContext *context, BYTE confirmBlockNum, UINT16 wTimestamp);
    BOOL onChannelIdAssigned(RdpsndServerContext *context, UINT32 channelId);
    void runTxLoop(std::stop_token stopToken, size_t chunkFrames, size_t chunkSamples);

    static void activatedCallback(RdpsndServerContext *context)
    {
        if (context && context->data) {
            reinterpret_cast<AudioStream *>(context->data)->d->onActivated(context);
        }
    }

    static UINT confirmBlockCallback(RdpsndServerContext *context, BYTE confirmBlockNum, UINT16 wTimestamp)
    {
        if (context && context->data) {
            return reinterpret_cast<AudioStream *>(context->data)->d->onConfirmBlock(context, confirmBlockNum, wTimestamp);
        }
        return CHANNEL_RC_OK;
    }

    static BOOL channelIdAssignedCallback(RdpsndServerContext *context, UINT32 channelId)
    {
        if (context && context->data) {
            return reinterpret_cast<AudioStream *>(context->data)->d->onChannelIdAssigned(context, channelId);
        }
        return TRUE;
    }
};

std::optional<uint16_t> AudioStream::selectBestClientFormat(const AUDIO_FORMAT *formats, uint16_t count)
{
    if (!formats || count == 0) {
        return std::nullopt;
    }

    int bestScore = -1;
    std::optional<uint16_t> bestIndex;
    for (uint16_t i = 0; i < count; ++i) {
        const int score = scorePcmFormat(formats[i]);
        if (score > bestScore) {
            bestScore = score;
            bestIndex = i;
        }
    }
    return bestIndex;
}

bool AudioStream::isChunkAudible(const int16_t *samples, size_t sampleCount)
{
    if (!samples || sampleCount == 0) {
        return false;
    }
    for (size_t i = 0; i < sampleCount; ++i) {
        if (samples[i] > 1 || samples[i] < -1) {
            return true;
        }
    }
    return false;
}

AudioStream::AudioStream(RdpConnection *session)
    : QObject(nullptr)
    , d(std::make_unique<Private>(this))
{
    d->session = session;
}

AudioStream::~AudioStream()
{
    close();
}

bool AudioStream::initialize(bool useDynamicChannel)
{
    if (d->initialized.load(std::memory_order_acquire)) {
        return true;
    }
    if (!d->session || (d->session->state() != RdpConnection::State::Activated && d->session->state() != RdpConnection::State::Streaming)) {
        qCWarning(KRDP) << "Refusing to initialize RDPSND audio stream before authentication";
        return false;
    }

#ifndef HAVE_PIPEWIRE_AUDIO
    Q_UNUSED(useDynamicChannel);
    qCWarning(KRDP) << "RDPSND audio redirection unavailable: built without libpipewire-0.3";
    return false;
#else
    auto *peer = d->session->rdpPeer();
    if (!peer || !peer->context) {
        return false;
    }
    auto *peerContext = reinterpret_cast<PeerContext *>(peer->context);

    std::lock_guard lock(d->rdpsndMutex);
    if (d->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    d->closing.store(false, std::memory_order_release);
    d->activated.store(false, std::memory_order_release);
    d->inFlightBlocks.store(0, std::memory_order_release);

    d->rdpsndContext = Private::RdpsndServerContextPtr{rdpsnd_server_context_new(peerContext->virtualChannelManager), rdpsnd_server_context_free};
    if (!d->rdpsndContext) {
        qCWarning(KRDP) << "Failed creating RDPSND server context";
        return false;
    }

    auto *ctx = d->rdpsndContext.get();
    ctx->data = this;
    ctx->rdpcontext = peer->context;
    ctx->use_dynamic_virtual_channel = useDynamicChannel ? TRUE : FALSE;
    ctx->server_formats = d->serverFormats.data();
    ctx->num_server_formats = d->serverFormats.size();
    ctx->src_format = &d->srcFormat;
    ctx->latency = 5;
    ctx->Activated = Private::activatedCallback;
    ctx->ConfirmBlock = Private::confirmBlockCallback;
    ctx->ChannelIdAssigned = Private::channelIdAssignedCallback;

    const UINT status = ctx->Initialize(ctx, TRUE);
    if (status != CHANNEL_RC_OK) {
        qCWarning(KRDP) << "Failed to initialize RDPSND audio channel (dvc=" << useDynamicChannel << ", status=" << status << ")";
        ctx->server_formats = nullptr;
        ctx->num_server_formats = 0;
        ctx->src_format = nullptr;
        d->rdpsndContext.reset();
        return false;
    }

    d->initialized.store(true, std::memory_order_release);
    d->enabled.store(true, std::memory_order_release);
    qCInfo(KRDP) << "RDPSND audio channel initialized (dvc=" << useDynamicChannel << ", backend=pipewire)";
    return true;
#endif
}

void AudioStream::close()
{
    d->closing.store(true, std::memory_order_release);
    d->enabled.store(false, std::memory_order_release);
    d->activated.store(false, std::memory_order_release);
    d->signalWake();

    // Stop FreeRDP's internal rdpsnd thread OUTSIDE rdpsndMutex so an in-flight
    // Activated callback cannot deadlock waiting on rdpsndMutex while Stop() joins it.
    RdpsndServerContext *ctxToStop = nullptr;
    {
        std::lock_guard lock(d->rdpsndMutex);
        ctxToStop = d->rdpsndContext.get();
    }
    if (ctxToStop && ctxToStop->Stop) {
        ctxToStop->Stop(ctxToStop);
    }

    {
        std::lock_guard captureLock(d->captureLifecycleMutex);
#ifdef HAVE_PIPEWIRE_AUDIO
        d->stopPipeWireCaptureLocked();
#endif
        if (d->txThread.joinable()) {
            d->txThread.request_stop();
            d->signalWake();
            d->txThread.join();
        }
        d->ringBuffer.reset();
        if (d->wakeEventFd >= 0) {
            ::close(d->wakeEventFd);
            d->wakeEventFd = -1;
        }
    }

    {
        std::lock_guard lock(d->rdpsndMutex);
        if (d->rdpsndContext) {
            auto *ctx = d->rdpsndContext.get();
            ctx->server_formats = nullptr;
            ctx->num_server_formats = 0;
            ctx->src_format = nullptr;
            d->rdpsndContext.reset();
        }
    }

    d->initialized.store(false, std::memory_order_release);
    d->inFlightBlocks.store(0, std::memory_order_release);
}

bool AudioStream::enabled() const
{
    return d->enabled.load(std::memory_order_acquire);
}

bool AudioStream::activated() const
{
    return d->activated.load(std::memory_order_acquire);
}

BOOL AudioStream::Private::onChannelIdAssigned(RdpsndServerContext *, UINT32 channelId)
{
    qCInfo(KRDP) << "RDPSND dynamic channel id assigned:" << channelId;
    return TRUE;
}

UINT AudioStream::Private::onConfirmBlock(RdpsndServerContext *, BYTE confirmBlockNum, UINT16 wTimestamp)
{
    int current = inFlightBlocks.load(std::memory_order_relaxed);
    while (current > 0 && !inFlightBlocks.compare_exchange_weak(current, current - 1, std::memory_order_acq_rel)) { }

    const uint16_t sentTs = sentTimestamps[confirmBlockNum].load(std::memory_order_acquire);
    const int delay = static_cast<uint16_t>(wTimestamp - sentTs);
    if (delay < 5000) { // ignore wrapped / bogus confirms
        const int prev = clientDelayMs.load(std::memory_order_relaxed);
        clientDelayMs.store(prev < 0 ? delay : (prev * 7 + delay) / 8, std::memory_order_release);
        if (delay > clientDelayPeakMs.load(std::memory_order_relaxed)) {
            clientDelayPeakMs.store(delay, std::memory_order_relaxed);
        }
    }
    const auto nowMs =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
    lastConfirmSteadyMs.store(nowMs, std::memory_order_release);
    return CHANNEL_RC_OK;
}

#ifdef HAVE_PIPEWIRE_AUDIO
void AudioStream::Private::pwStateChangedCallback(void *, enum pw_stream_state oldState, enum pw_stream_state state, const char *error)
{
    if (state == PW_STREAM_STATE_ERROR) {
        qCWarning(KRDP) << "RDPSND PipeWire audio stream error:" << (error ? error : "unknown");
    } else {
        qCInfo(KRDP) << "RDPSND PipeWire audio stream state:" << pw_stream_state_as_string(oldState) << "->" << pw_stream_state_as_string(state);
    }
}

void AudioStream::Private::pwProcessCallback(void *userdata)
{
    // Real-time PipeWire audio callback: strictly wait-free, zero heap allocations, zero mutexes.
    auto *self = reinterpret_cast<AudioStream::Private *>(userdata);
    if (!self || !self->pwStream) {
        return;
    }

    pw_buffer *pwBuf = pw_stream_dequeue_buffer(self->pwStream);
    if (!pwBuf) {
        return;
    }

    if (!self->closing.load(std::memory_order_acquire) && pwBuf->buffer && pwBuf->buffer->n_datas > 0) {
        const spa_data &spaData = pwBuf->buffer->datas[0];
        if (spaData.data && spaData.chunk && spaData.chunk->size > 0) {
            const uint32_t offset = spaData.chunk->offset;
            const uint32_t size = spaData.chunk->size;
            if (offset <= spaData.maxsize && size <= spaData.maxsize - offset) {
                const size_t nSamples = size / sizeof(int16_t);
                const auto *src = reinterpret_cast<const int16_t *>(static_cast<const uint8_t *>(spaData.data) + offset);
                self->ringBuffer.write(src, nSamples);
                if (self->ringBuffer.available() >= self->samplesPerChunk) {
                    self->signalWake();
                }
            }
        }
    }

    pw_stream_queue_buffer(self->pwStream, pwBuf);
}

bool AudioStream::Private::startPipeWireCaptureLocked(uint32_t sampleRate, uint16_t channels)
{
    stopPipeWireCaptureLocked();

    static std::once_flag pwInitOnce;
    std::call_once(pwInitOnce, []() {
        pw_init(nullptr, nullptr);
    });

    // ~10 ms RDPSND packets (480 frames @ 48 kHz). 5 ms packets caused frequent client underruns
    // on VMBus scheduling jitter, which made the Windows client grow its playout buffer over time.
    framesPerChunk = std::max<size_t>(240, sampleRate / 100);
    samplesPerChunk = framesPerChunk * channels;
    // Bounded ring buffer (~80 ms minimum, rounded to power-of-two) allocated ONCE before RT thread starts.
    ringBuffer.configure(samplesPerChunk * 8);

    if (wakeEventFd < 0) {
        wakeEventFd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (wakeEventFd < 0) {
            qCWarning(KRDP) << "RDPSND failed to create wake eventfd";
            return false;
        }
    }

    pwLoop = pw_thread_loop_new("krdp-audio", nullptr);
    if (!pwLoop) {
        qCWarning(KRDP) << "RDPSND failed to create PipeWire thread loop";
        return false;
    }

    if (pw_thread_loop_start(pwLoop) < 0) {
        qCWarning(KRDP) << "RDPSND failed to start PipeWire thread loop";
        pw_thread_loop_destroy(pwLoop);
        pwLoop = nullptr;
        return false;
    }

    pwStreamEvents = {};
    pwStreamEvents.version = PW_VERSION_STREAM_EVENTS;
    pwStreamEvents.state_changed = &AudioStream::Private::pwStateChangedCallback;
    pwStreamEvents.process = &AudioStream::Private::pwProcessCallback;

    char latencySpec[64] = {};
    std::snprintf(latencySpec, sizeof(latencySpec), "%zu/%u", framesPerChunk, sampleRate);
    char maxLatencySpec[64] = {};
    std::snprintf(maxLatencySpec, sizeof(maxLatencySpec), "%zu/%u", framesPerChunk, sampleRate);

    pw_thread_loop_lock(pwLoop);

    pw_properties *props = pw_properties_new(PW_KEY_MEDIA_TYPE,
                                             "Audio",
                                             PW_KEY_MEDIA_CLASS,
                                             "Audio/Sink",
                                             PW_KEY_APP_NAME,
                                             "KRDP Server",
                                             PW_KEY_NODE_NAME,
                                             "krdp-rdpsnd-sink",
                                             PW_KEY_NODE_DESCRIPTION,
                                             "Remote Audio (RDP)",
                                             PW_KEY_NODE_NICK,
                                             "Remote Audio",
                                             PW_KEY_DEVICE_CLASS,
                                             "sound",
                                             PW_KEY_DEVICE_FORM_FACTOR,
                                             "speaker",
                                             PW_KEY_DEVICE_ICON_NAME,
                                             "audio-card",
                                             PW_KEY_NODE_VIRTUAL,
                                             "false",
                                             PW_KEY_PRIORITY_SESSION,
                                             "2000",
                                             PW_KEY_NODE_LATENCY,
                                             latencySpec,
                                             PW_KEY_NODE_MAX_LATENCY,
                                             maxLatencySpec,
                                             "session.suspend-timeout-seconds",
                                             "0",
                                             "monitor.channel-volumes",
                                             "true",
                                             nullptr);

    pwStream = pw_stream_new_simple(pw_thread_loop_get_loop(pwLoop), "Remote Audio (RDP)", props, &pwStreamEvents, this);
    if (!pwStream) {
        pw_thread_loop_unlock(pwLoop);
        qCWarning(KRDP) << "RDPSND failed to create PipeWire virtual Audio/Sink stream";
        stopPipeWireCaptureLocked();
        return false;
    }

    spa_audio_info_raw rawInfo = {};
    rawInfo.format = SPA_AUDIO_FORMAT_S16_LE;
    rawInfo.rate = sampleRate;
    rawInfo.channels = channels;
    if (channels == 2) {
        rawInfo.position[0] = SPA_AUDIO_CHANNEL_FL;
        rawInfo.position[1] = SPA_AUDIO_CHANNEL_FR;
    } else if (channels == 1) {
        rawInfo.position[0] = SPA_AUDIO_CHANNEL_MONO;
    }

    uint8_t podBuf[1024] = {};
    spa_pod_builder builder = SPA_POD_BUILDER_INIT(podBuf, sizeof(podBuf));
    const spa_pod *params[1] = {spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &rawInfo)};

    // Virtual Audio/Sink: WirePlumber automatically promotes it as default output sink
    // (visible in KDE Plasma volume control) and routes desktop audio into this stream.
    const auto flags = static_cast<pw_stream_flags>(PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS);
    const int rc = pw_stream_connect(pwStream, PW_DIRECTION_INPUT, PW_ID_ANY, flags, params, 1);
    pw_thread_loop_unlock(pwLoop);

    if (rc < 0) {
        qCWarning(KRDP) << "RDPSND pw_stream_connect failed:" << rc;
        stopPipeWireCaptureLocked();
        return false;
    }

    qCInfo(KRDP) << "RDPSND PipeWire virtual Audio/Sink started:" << sampleRate << "Hz," << channels << "ch (" << framesPerChunk
                 << "frames/chunk, ringCapacity=" << ringBuffer.capacity() << "samples)";
    return true;
}

void AudioStream::Private::stopPipeWireCaptureLocked()
{
    if (pwLoop) {
        pw_thread_loop_lock(pwLoop);
        if (pwStream) {
            pw_stream_destroy(pwStream);
            pwStream = nullptr;
        }
        pw_thread_loop_unlock(pwLoop);
        pw_thread_loop_stop(pwLoop);
        pw_thread_loop_destroy(pwLoop);
        pwLoop = nullptr;
    }
}
#endif

void AudioStream::Private::onActivated(RdpsndServerContext *context)
{
    if (closing.load(std::memory_order_acquire) || !context) {
        return;
    }

    for (uint16_t i = 0; i < context->num_client_formats; ++i) {
        const AUDIO_FORMAT &f = context->client_formats[i];
        qCInfo(KRDP) << "RDPSND client format" << i << ": tag=" << f.wFormatTag << "rate=" << f.nSamplesPerSec << "ch=" << f.nChannels
                     << "bits=" << f.wBitsPerSample;
    }

    auto selectedIdx = AudioStream::selectBestClientFormat(context->client_formats, context->num_client_formats);
    if (!selectedIdx) {
        qCWarning(KRDP) << "RDPSND client offered no compatible 16-bit PCM audio formats (count=" << context->num_client_formats << ")";
        return;
    }

    // Diagnostic override: KRDP_RDPSND_RATE=44100 forces a specific client sample rate (best channel count wins).
    if (const QByteArray forced = qgetenv("KRDP_RDPSND_RATE"); !forced.isEmpty()) {
        const uint32_t wantedRate = forced.toUInt();
        std::optional<uint16_t> overrideIdx;
        for (uint16_t i = 0; i < context->num_client_formats; ++i) {
            const AUDIO_FORMAT &f = context->client_formats[i];
            if (f.wFormatTag == WAVE_FORMAT_PCM && f.wBitsPerSample == 16 && f.nSamplesPerSec == wantedRate && f.nChannels >= 1 && f.nChannels <= 2
                && (!overrideIdx || f.nChannels > context->client_formats[*overrideIdx].nChannels)) {
                overrideIdx = i;
            }
        }
        if (overrideIdx) {
            qCInfo(KRDP) << "RDPSND KRDP_RDPSND_RATE override selects client format" << *overrideIdx;
            selectedIdx = overrideIdx;
        }
    }

    const AUDIO_FORMAT &clientFmt = context->client_formats[*selectedIdx];
    const uint32_t sampleRate = clientFmt.nSamplesPerSec;
    const uint16_t channels = clientFmt.nChannels;

    {
        std::lock_guard lock(rdpsndMutex);
        if (closing.load(std::memory_order_acquire) || !rdpsndContext) {
            return;
        }
        srcFormat = makePcmFormat(sampleRate, channels, 16);
        context->src_format = &srcFormat;
        const UINT status = context->SelectFormat(context, *selectedIdx);
        if (status != CHANNEL_RC_OK) {
            qCWarning(KRDP) << "RDPSND SelectFormat failed for index" << *selectedIdx << "status=" << status;
            return;
        }
        selectedFormatIndex.store(*selectedIdx, std::memory_order_release);
    }

    activated.store(true, std::memory_order_release);
    qCInfo(KRDP) << "RDPSND audio stream activated: formatIndex=" << *selectedIdx << "rate=" << sampleRate << "ch=" << channels
                 << "clientVersion=" << context->clientVersion << "dvc=" << bool(context->use_dynamic_virtual_channel);

#ifdef HAVE_PIPEWIRE_AUDIO
    std::lock_guard captureLock(captureLifecycleMutex);
    if (closing.load(std::memory_order_acquire)) {
        return;
    }
    if (txThread.joinable()) {
        txThread.request_stop();
        signalWake();
        txThread.join();
    }
    if (!startPipeWireCaptureLocked(sampleRate, channels)) {
        return;
    }
    const size_t chunkFrames = framesPerChunk;
    const size_t chunkSamples = samplesPerChunk;
    clientDelayMs.store(-1, std::memory_order_release);
    clientDelayPeakMs.store(0, std::memory_order_relaxed);
    txThread = std::jthread([this, chunkFrames, chunkSamples](std::stop_token token) {
        runTxLoop(token, chunkFrames, chunkSamples);
    });
    pthread_setname_np(txThread.native_handle(), "krdp_audio_tx");
#endif
}

void AudioStream::Private::runTxLoop(std::stop_token stopToken, size_t chunkFrames, size_t chunkSamples)
{
    const auto startTime = std::chrono::steady_clock::now();
    constexpr int SilenceTailChunks = 30; // 300 ms tail at 10 ms/chunk
    constexpr int MaxInFlightBlocks = 12; // backstop only (~120 ms); client delay control does the real work
    constexpr size_t MaxBufferedChunksBeforeTrim = 4; // server-side backlog above ~40 ms is stale
    // Client playout delay control: above HighWater, drop chunks (preferring quiet ones) until LowWater.
    constexpr int DelayHighWaterMs = 250;
    constexpr int DelayLowWaterMs = 150;
    constexpr int DelayForceDropMs = 500;
    constexpr int QuietPeak = 2048; // ~-24 dBFS
    constexpr int MinChunksBetweenDriftDrops = 3;
    int silentChunksRemaining = 0;
    bool draining = false;
    int chunksSinceDriftDrop = MinChunksBetweenDriftDrops;

    uint64_t statSent = 0, statTrimmed = 0, statInFlightDrops = 0, statDriftDrops = 0;
    auto lastStatLog = startTime;

    std::vector<int16_t> chunk(chunkSamples);

    while (!stopToken.stop_requested() && !closing.load(std::memory_order_acquire)) {
        if (const auto now = std::chrono::steady_clock::now(); now - lastStatLog >= std::chrono::seconds(10)) {
            lastStatLog = now;
            if (statSent > 0 || statTrimmed > 0 || statInFlightDrops > 0 || statDriftDrops > 0) {
                qCInfo(KRDP) << "RDPSND stats (10s): sent=" << statSent << "trimmed=" << statTrimmed << "inFlightDrops=" << statInFlightDrops
                             << "driftDrops=" << statDriftDrops << "clientDelayMs=" << clientDelayMs.load(std::memory_order_acquire)
                             << "peak=" << clientDelayPeakMs.exchange(0, std::memory_order_relaxed)
                             << "inFlight=" << inFlightBlocks.load(std::memory_order_relaxed);
            }
            statSent = statTrimmed = statInFlightDrops = statDriftDrops = 0;
        }

        const size_t avail = ringBuffer.available();
        if (avail < chunkSamples) {
            if (wakeEventFd >= 0) {
                pollfd pfd{};
                pfd.fd = wakeEventFd;
                pfd.events = POLLIN;
                const int rc = ::poll(&pfd, 1, 5);
                if (rc > 0 && (pfd.revents & POLLIN)) {
                    uint64_t drained = 0;
                    const ssize_t ignored = ::read(wakeEventFd, &drained, sizeof(drained));
                    (void)ignored;
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
            continue;
        }

        // Server-side backlog is bounded; anything beyond ~40 ms is stale.
        if (avail > chunkSamples * MaxBufferedChunksBeforeTrim) {
            ringBuffer.discard(avail - chunkSamples);
            ++statTrimmed;
        }

        const size_t got = ringBuffer.read(chunk.data(), chunkSamples);
        if (got < chunkSamples) {
            continue;
        }

        if (AudioStream::isChunkAudible(chunk.data(), chunkSamples)) {
            silentChunksRemaining = SilenceTailChunks;
        } else if (silentChunksRemaining > 0) {
            --silentChunksRemaining;
        } else {
            continue;
        }

        const auto nowSteady = std::chrono::steady_clock::now();
        const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(nowSteady.time_since_epoch()).count());
        const uint32_t elapsedMs = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(nowSteady - startTime).count());
        const uint16_t wTimestamp = static_cast<uint16_t>(elapsedMs & 0xFFFFu);

        if (inFlightBlocks.load(std::memory_order_acquire) >= MaxInFlightBlocks) {
            const uint64_t lastConf = lastConfirmSteadyMs.load(std::memory_order_acquire);
            if (lastConf != 0 && (nowMs - lastConf) > 1000) { // only recover from lost confirms; otherwise in-flight cap is real backpressure
                inFlightBlocks.store(0, std::memory_order_release);
            } else {
                ++statInFlightDrops;
                continue;
            }
        }

        // Client playout delay control (hysteresis). Dropping whole chunks is the only lever
        // RDPSND gives us to shrink the Windows client's playout queue during continuous audio.
        const int delay = clientDelayMs.load(std::memory_order_acquire);
        if (delay > DelayHighWaterMs) {
            draining = true;
        } else if (delay >= 0 && delay <= DelayLowWaterMs) {
            draining = false;
        }
        ++chunksSinceDriftDrop;
        if (draining && chunksSinceDriftDrop > MinChunksBetweenDriftDrops) {
            int peak = 0;
            for (size_t i = 0; i < chunkSamples; ++i) {
                peak = std::max(peak, std::abs(static_cast<int>(chunk[i])));
            }
            if (peak < QuietPeak || delay > DelayForceDropMs) {
                chunksSinceDriftDrop = 0;
                ++statDriftDrops;
                // Assume one chunk less is queued until the next confirm refreshes the estimate.
                const int chunkMs = static_cast<int>(chunkFrames * 1000 / std::max<uint32_t>(1, srcFormat.nSamplesPerSec));
                int expected = delay;
                clientDelayMs.compare_exchange_strong(expected, std::max(0, delay - chunkMs), std::memory_order_acq_rel);
                continue;
            }
        }

        UINT sendStatus = CHANNEL_RC_OK;
        {
            std::lock_guard lock(rdpsndMutex);
            if (closing.load(std::memory_order_acquire) || !rdpsndContext) {
                break;
            }
            sentTimestamps[rdpsndContext->block_no].store(wTimestamp, std::memory_order_release);
            // Prefer SendSamples2 (SNDC_WAVE2) for raw S16LE PCM to send exact samples
            // directly without routing through freerdp_dsp_encode() (which in FreeRDP 3.x
            // corrupts signed 16-bit PCM by flipping the sign bit / offsetting by -32768).
            if (rdpsndContext->clientVersion >= 8 && rdpsndContext->SendSamples2) {
                const uint16_t fmtNo = selectedFormatIndex.load(std::memory_order_acquire);
                sendStatus = rdpsndContext->SendSamples2(rdpsndContext.get(), fmtNo, chunk.data(), chunkSamples * sizeof(int16_t), wTimestamp, elapsedMs);
            } else if (rdpsndContext->SendSamples) {
                sendStatus = rdpsndContext->SendSamples(rdpsndContext.get(), chunk.data(), chunkFrames, wTimestamp);
            } else {
                break;
            }
        }

        if (sendStatus != CHANNEL_RC_OK) {
            qCWarning(KRDP) << "RDPSND SendSamples failed with status" << sendStatus;
            break;
        }
        inFlightBlocks.fetch_add(1, std::memory_order_acq_rel);
        ++statSent;
    }

    qCInfo(KRDP) << "RDPSND audio transmit loop exited (droppedSamples=" << ringBuffer.droppedSamples() << ")";
}

} // namespace KRdp

#include "moc_AudioStream.cpp"
