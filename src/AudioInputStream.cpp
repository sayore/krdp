// SPDX-FileCopyrightText: 2026 Amelie Krippner <amykrippner@outlook.de>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "AudioInputStream.h"
#include "AudioStream.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>

#include <freerdp/channels/audin.h>
#include <freerdp/freerdp.h>
#include <freerdp/peer.h>
#include <freerdp/server/audin.h>
#include <winpr/stream.h>

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
constexpr AUDIO_FORMAT makePcmInputFormat(uint32_t sampleRate, uint16_t channels, uint16_t bitsPerSample = 16)
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

int scoreInputPcmFormat(const AUDIO_FORMAT &fmt)
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
    // Prefer mono for microphone input (widest client compatibility and lower bandwidth),
    // with 48 kHz > 44.1 kHz > 32 kHz > 22.05 kHz > 16 kHz.
    if (fmt.nChannels == 1) {
        score += 20;
    } else {
        score += 10;
    }
    if (fmt.nSamplesPerSec == 48000) {
        score += 100;
    } else if (fmt.nSamplesPerSec == 44100) {
        score += 80;
    } else if (fmt.nSamplesPerSec == 32000) {
        score += 60;
    } else if (fmt.nSamplesPerSec == 24000) {
        score += 50;
    } else if (fmt.nSamplesPerSec == 22050) {
        score += 40;
    } else if (fmt.nSamplesPerSec == 16000) {
        score += 30;
    }
    return score;
}
} // namespace

class KRDP_NO_EXPORT AudioInputStream::Private
{
public:
    using AudinServerContextPtr = std::unique_ptr<audin_server_context, decltype(&audin_server_context_free)>;

    explicit Private(AudioInputStream *qq)
        : q(qq)
    {
    }

    AudioInputStream *q = nullptr;
    RdpConnection *session = nullptr;

    std::mutex audinMutex;
    AudinServerContextPtr audinContext = AudinServerContextPtr(nullptr, audin_server_context_free);

    std::array<AUDIO_FORMAT, 5> serverFormats = {
        makePcmInputFormat(48000, 1, 16),
        makePcmInputFormat(48000, 2, 16),
        makePcmInputFormat(44100, 1, 16),
        makePcmInputFormat(44100, 2, 16),
        makePcmInputFormat(16000, 1, 16),
    };

    AUDIO_FORMAT negotiatedFormat = makePcmInputFormat(48000, 1, 16);
    uint32_t negotiatedFormatIndex = 0;
    bool formatsNegotiated = false;
    bool openPduSent = false;

    std::atomic<bool> initialized{false};
    std::atomic<bool> enabled{false};
    std::atomic<bool> capturing{false};
    std::atomic<bool> closing{false};

    // Demand-driven capture control (decouples PipeWire state callbacks from FreeRDP channel I/O).
    std::mutex ctrlMutex;
    std::condition_variable ctrlCv;
    bool wantCapture = false;
    bool ctrlPending = false;
    std::jthread ctrlThread;

    // Pre-allocated lock-free SPSC ring buffer: FreeRDP AUDIN Data callback -> PipeWire RT source callback.
    std::mutex pwLifecycleMutex;
    size_t framesPerChunk = 480;
    uint16_t negotiatedChannels = 1;
    uint32_t negotiatedSampleRate = 48000;
    AudioStream::PcmRingBuffer ringBuffer;

#ifdef HAVE_PIPEWIRE_AUDIO
    pw_thread_loop *pwLoop = nullptr;
    pw_stream *pwStream = nullptr;
    pw_stream_events pwStreamEvents = {};

    static void pwStateChangedCallback(void *userdata, enum pw_stream_state oldState, enum pw_stream_state state, const char *error);
    static void pwProcessCallback(void *userdata);
    bool ensurePipeWireSourceLocked(uint32_t sampleRate, uint16_t channels);
    void stopPipeWireSourceLocked();
#endif

    void requestCaptureState(bool active);
    void runControlLoop(std::stop_token stopToken);
    UINT sendOpenPduLocked(audin_server_context *ctx);

    BOOL onChannelIdAssigned(audin_server_context *ctx, UINT32 channelId);
    UINT onReceiveVersion(audin_server_context *ctx, const SNDIN_VERSION *version);
    UINT onReceiveFormats(audin_server_context *ctx, const SNDIN_FORMATS *formats);
    UINT onOpenReply(audin_server_context *ctx, const SNDIN_OPEN_REPLY *reply);
    UINT onIncomingData(audin_server_context *ctx, const SNDIN_DATA_INCOMING *incoming);
    UINT onData(audin_server_context *ctx, const SNDIN_DATA *data);
    UINT onReceiveFormatChange(audin_server_context *ctx, const SNDIN_FORMATCHANGE *change);

    static BOOL channelIdAssignedCb(audin_server_context *ctx, UINT32 channelId)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onChannelIdAssigned(ctx, channelId) : TRUE;
    }
    static UINT receiveVersionCb(audin_server_context *ctx, const SNDIN_VERSION *version)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onReceiveVersion(ctx, version) : CHANNEL_RC_OK;
    }
    static UINT receiveFormatsCb(audin_server_context *ctx, const SNDIN_FORMATS *formats)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onReceiveFormats(ctx, formats) : CHANNEL_RC_OK;
    }
    static UINT openReplyCb(audin_server_context *ctx, const SNDIN_OPEN_REPLY *reply)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onOpenReply(ctx, reply) : CHANNEL_RC_OK;
    }
    static UINT incomingDataCb(audin_server_context *ctx, const SNDIN_DATA_INCOMING *incoming)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onIncomingData(ctx, incoming) : CHANNEL_RC_OK;
    }
    static UINT dataCb(audin_server_context *ctx, const SNDIN_DATA *data)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onData(ctx, data) : CHANNEL_RC_OK;
    }
    static UINT receiveFormatChangeCb(audin_server_context *ctx, const SNDIN_FORMATCHANGE *change)
    {
        return (ctx && ctx->userdata) ? reinterpret_cast<AudioInputStream *>(ctx->userdata)->d->onReceiveFormatChange(ctx, change) : CHANNEL_RC_OK;
    }
};

std::optional<uint32_t> AudioInputStream::selectBestClientFormat(const AUDIO_FORMAT *formats, uint32_t count)
{
    if (!formats || count == 0) {
        return std::nullopt;
    }

    int bestScore = -1;
    std::optional<uint32_t> bestIdx;
    for (uint32_t i = 0; i < count; ++i) {
        const int score = scoreInputPcmFormat(formats[i]);
        if (score > bestScore) {
            bestScore = score;
            bestIdx = i;
        }
    }
    return bestIdx;
}

AudioInputStream::AudioInputStream(RdpConnection *session)
    : QObject(nullptr)
    , d(std::make_unique<Private>(this))
{
    d->session = session;
}

AudioInputStream::~AudioInputStream()
{
    close();
}

bool AudioInputStream::initialize()
{
    if (d->initialized.load(std::memory_order_acquire)) {
        return true;
    }
    if (!d->session || (d->session->state() != RdpConnection::State::Activated && d->session->state() != RdpConnection::State::Streaming)) {
        qCWarning(KRDP) << "Refusing to initialize AUDIN microphone stream before authentication";
        return false;
    }

#ifndef HAVE_PIPEWIRE_AUDIO
    qCWarning(KRDP) << "AUDIN microphone redirection unavailable: built without libpipewire-0.3";
    return false;
#else
    auto *peer = d->session->rdpPeer();
    if (!peer || !peer->context) {
        return false;
    }
    auto *peerContext = reinterpret_cast<PeerContext *>(peer->context);

    std::lock_guard lock(d->audinMutex);
    if (d->initialized.load(std::memory_order_acquire)) {
        return true;
    }

    d->closing.store(false, std::memory_order_release);
    d->capturing.store(false, std::memory_order_release);
    d->formatsNegotiated = false;
    d->openPduSent = false;

    d->audinContext = Private::AudinServerContextPtr{audin_server_context_new(peerContext->virtualChannelManager), audin_server_context_free};
    if (!d->audinContext) {
        qCWarning(KRDP) << "Failed creating AUDIN server context";
        return false;
    }

    auto *ctx = d->audinContext.get();
    ctx->userdata = this;
    ctx->rdpcontext = peer->context;
    ctx->serverVersion = SNDIN_VERSION_Version_2;
    ctx->ChannelIdAssigned = Private::channelIdAssignedCb;
    ctx->ReceiveVersion = Private::receiveVersionCb;
    ctx->ReceiveFormats = Private::receiveFormatsCb;
    ctx->OpenReply = Private::openReplyCb;
    ctx->IncomingData = Private::incomingDataCb;
    ctx->Data = Private::dataCb;
    ctx->ReceiveFormatChange = Private::receiveFormatChangeCb;

    if (!audin_server_set_formats(ctx, static_cast<SSIZE_T>(d->serverFormats.size()), d->serverFormats.data())) {
        qCWarning(KRDP) << "Failed setting AUDIN server formats";
        d->audinContext.reset();
        return false;
    }

    if (!ctx->Open(ctx)) {
        qCWarning(KRDP) << "Failed to open AUDIN dynamic virtual channel (client may have microphone redirection disabled)";
        d->audinContext.reset();
        return false;
    }

    d->ctrlThread = std::jthread([this](std::stop_token token) {
        d->runControlLoop(token);
    });
    pthread_setname_np(d->ctrlThread.native_handle(), "krdp_audin_ctrl");

    d->initialized.store(true, std::memory_order_release);
    d->enabled.store(true, std::memory_order_release);
    qCInfo(KRDP) << "AUDIN microphone channel initialized (demand-driven capture)";
    return true;
#endif
}

void AudioInputStream::close()
{
    d->closing.store(true, std::memory_order_release);
    d->enabled.store(false, std::memory_order_release);
    d->capturing.store(false, std::memory_order_release);

    {
        std::lock_guard cLock(d->ctrlMutex);
        d->wantCapture = false;
        d->ctrlPending = true;
    }
    d->ctrlCv.notify_all();

    if (d->ctrlThread.joinable()) {
        d->ctrlThread.request_stop();
        d->ctrlCv.notify_all();
        d->ctrlThread.join();
    }

    // Close AUDIN channel thread outside audinMutex to prevent callback lock inversion.
    audin_server_context *ctxToClose = nullptr;
    {
        std::lock_guard lock(d->audinMutex);
        ctxToClose = d->audinContext.get();
    }
    if (ctxToClose && ctxToClose->IsOpen && ctxToClose->IsOpen(ctxToClose) && ctxToClose->Close) {
        (void)ctxToClose->Close(ctxToClose);
    }

    {
        std::lock_guard pwLock(d->pwLifecycleMutex);
#ifdef HAVE_PIPEWIRE_AUDIO
        d->stopPipeWireSourceLocked();
#endif
        d->ringBuffer.reset();
    }

    {
        std::lock_guard lock(d->audinMutex);
        d->formatsNegotiated = false;
        d->openPduSent = false;
        d->audinContext.reset();
    }

    d->initialized.store(false, std::memory_order_release);
}

bool AudioInputStream::enabled() const
{
    return d->enabled.load(std::memory_order_acquire);
}

bool AudioInputStream::capturing() const
{
    return d->capturing.load(std::memory_order_acquire);
}

void AudioInputStream::Private::requestCaptureState(bool active)
{
    {
        std::lock_guard cLock(ctrlMutex);
        if (wantCapture == active) {
            return;
        }
        wantCapture = active;
        ctrlPending = true;
    }
    ctrlCv.notify_one();
}

UINT AudioInputStream::Private::sendOpenPduLocked(audin_server_context *ctx)
{
    if (!ctx || !ctx->SendOpen || !formatsNegotiated || openPduSent) {
        return CHANNEL_RC_OK;
    }

    SNDIN_OPEN openPdu = {};
    openPdu.FramesPerPacket = static_cast<UINT32>(std::max<size_t>(160, negotiatedFormat.nSamplesPerSec / 100));
    openPdu.initialFormat = negotiatedFormatIndex;
    openPdu.captureFormat = negotiatedFormat;
    openPdu.ExtraFormatData = nullptr;

    const UINT rc = ctx->SendOpen(ctx, &openPdu);
    if (rc == CHANNEL_RC_OK) {
        openPduSent = true;
        qCInfo(KRDP) << "AUDIN SNDIN_OPEN sent (formatIndex=" << negotiatedFormatIndex << "rate=" << negotiatedFormat.nSamplesPerSec
                     << "ch=" << negotiatedFormat.nChannels << "framesPerPacket=" << openPdu.FramesPerPacket << ")";
    } else {
        qCWarning(KRDP) << "AUDIN SendOpen failed with status" << rc;
    }
    return rc;
}

void AudioInputStream::Private::runControlLoop(std::stop_token stopToken)
{
    while (!stopToken.stop_requested() && !closing.load(std::memory_order_acquire)) {
        bool desired = false;
        {
            std::unique_lock cLock(ctrlMutex);
            ctrlCv.wait(cLock, [&]() {
                return stopToken.stop_requested() || closing.load(std::memory_order_acquire) || ctrlPending;
            });
            if (stopToken.stop_requested() || closing.load(std::memory_order_acquire)) {
                break;
            }
            desired = wantCapture;
            ctrlPending = false;
        }

        if (desired) {
            std::lock_guard lock(audinMutex);
            if (!audinContext || closing.load(std::memory_order_acquire)) {
                continue;
            }
            auto *ctx = audinContext.get();
            if (ctx->IsOpen && !ctx->IsOpen(ctx)) {
                formatsNegotiated = false;
                openPduSent = false;
                if (!ctx->Open(ctx)) {
                    qCWarning(KRDP) << "AUDIN failed to re-open channel on demand";
                }
            } else if (formatsNegotiated && !openPduSent) {
                (void)sendOpenPduLocked(ctx);
            }
        } else {
            // Stop Windows host microphone recording cleanly by closing the AUDIO_INPUT DVC.
            audin_server_context *ctxToClose = nullptr;
            {
                std::lock_guard lock(audinMutex);
                if (audinContext && openPduSent) {
                    ctxToClose = audinContext.get();
                    openPduSent = false;
                    formatsNegotiated = false;
                }
            }
            if (ctxToClose && ctxToClose->IsOpen && ctxToClose->IsOpen(ctxToClose) && ctxToClose->Close) {
                qCInfo(KRDP) << "AUDIN closing AUDIO_INPUT channel (guest microphone idle)";
                (void)ctxToClose->Close(ctxToClose);
            }
            capturing.store(false, std::memory_order_release);
            ringBuffer.reset();
        }
    }
}

BOOL AudioInputStream::Private::onChannelIdAssigned(audin_server_context *, UINT32 channelId)
{
    qCInfo(KRDP) << "AUDIN dynamic channel id assigned:" << channelId;
    return TRUE;
}

UINT AudioInputStream::Private::onReceiveVersion(audin_server_context *ctx, const SNDIN_VERSION *version)
{
    if (closing.load(std::memory_order_acquire) || !ctx || !version) {
        return CHANNEL_RC_OK;
    }
    qCInfo(KRDP) << "AUDIN client version received:" << static_cast<uint32_t>(version->Version);

    SNDIN_FORMATS formatsPdu = {};
    formatsPdu.NumFormats = static_cast<UINT32>(serverFormats.size());
    formatsPdu.SoundFormats = serverFormats.data();
    const UINT rc = ctx->SendFormats(ctx, &formatsPdu);
    if (rc != CHANNEL_RC_OK) {
        qCWarning(KRDP) << "AUDIN SendFormats failed with status" << rc;
    }
    return rc;
}

UINT AudioInputStream::Private::onReceiveFormats(audin_server_context *ctx, const SNDIN_FORMATS *formats)
{
    if (closing.load(std::memory_order_acquire) || !ctx || !formats) {
        return CHANNEL_RC_OK;
    }

    const auto bestIdx = AudioInputStream::selectBestClientFormat(formats->SoundFormats, formats->NumFormats);
    if (!bestIdx) {
        qCWarning(KRDP) << "AUDIN client offered no compatible 16-bit PCM microphone formats (count=" << formats->NumFormats << ")";
        return CHANNEL_RC_OK;
    }

    const AUDIO_FORMAT chosen = formats->SoundFormats[*bestIdx];
    const uint32_t rate = chosen.nSamplesPerSec;
    const uint16_t ch = chosen.nChannels;

    bool shouldOpenNow = false;
    {
        std::lock_guard cLock(ctrlMutex);
        shouldOpenNow = wantCapture;
    }

    {
        std::lock_guard lock(audinMutex);
        negotiatedFormat = makePcmInputFormat(rate, ch, 16);
        negotiatedFormatIndex = *bestIdx;
        formatsNegotiated = true;
        openPduSent = false;
    }

    qCInfo(KRDP) << "AUDIN microphone format negotiated: index=" << *bestIdx << "rate=" << rate << "ch=" << ch;

#ifdef HAVE_PIPEWIRE_AUDIO
    {
        std::lock_guard pwLock(pwLifecycleMutex);
        if (!closing.load(std::memory_order_acquire)) {
            (void)ensurePipeWireSourceLocked(rate, ch);
        }
    }
#endif

    if (shouldOpenNow) {
        std::lock_guard lock(audinMutex);
        if (!closing.load(std::memory_order_acquire) && audinContext) {
            return sendOpenPduLocked(audinContext.get());
        }
    }

    return CHANNEL_RC_OK;
}

UINT AudioInputStream::Private::onOpenReply(audin_server_context *, const SNDIN_OPEN_REPLY *reply)
{
    if (!reply) {
        return CHANNEL_RC_OK;
    }
    if (reply->Result == 0) {
        capturing.store(true, std::memory_order_release);
        qCInfo(KRDP) << "AUDIN host microphone capture started (S_OK)";
    } else {
        capturing.store(false, std::memory_order_release);
        qCWarning(KRDP) << "AUDIN client declined microphone open: HRESULT=" << Qt::hex << reply->Result << Qt::dec;
    }
    return CHANNEL_RC_OK;
}

UINT AudioInputStream::Private::onIncomingData(audin_server_context *, const SNDIN_DATA_INCOMING *)
{
    return CHANNEL_RC_OK;
}

UINT AudioInputStream::Private::onData(audin_server_context *, const SNDIN_DATA *data)
{
    if (closing.load(std::memory_order_acquire) || !data || !data->Data) {
        return CHANNEL_RC_OK;
    }

    const size_t remaining = Stream_GetRemainingLength(data->Data);
    if (remaining < sizeof(int16_t)) {
        return CHANNEL_RC_OK;
    }
    const auto *samples = reinterpret_cast<const int16_t *>(Stream_Pointer(data->Data));
    const size_t nSamples = remaining / sizeof(int16_t);
    ringBuffer.write(samples, nSamples);
    return CHANNEL_RC_OK;
}

UINT AudioInputStream::Private::onReceiveFormatChange(audin_server_context *, const SNDIN_FORMATCHANGE *change)
{
    if (change) {
        qCInfo(KRDP) << "AUDIN client format change index:" << change->NewFormat;
    }
    return CHANNEL_RC_OK;
}

#ifdef HAVE_PIPEWIRE_AUDIO
void AudioInputStream::Private::pwStateChangedCallback(void *userdata, enum pw_stream_state oldState, enum pw_stream_state state, const char *error)
{
    auto *self = reinterpret_cast<AudioInputStream::Private *>(userdata);
    if (state == PW_STREAM_STATE_ERROR) {
        qCWarning(KRDP) << "AUDIN PipeWire microphone source error:" << (error ? error : "unknown");
    } else {
        qCInfo(KRDP) << "AUDIN PipeWire microphone source state:" << pw_stream_state_as_string(oldState) << "->" << pw_stream_state_as_string(state);
    }

    if (!self || self->closing.load(std::memory_order_acquire)) {
        return;
    }
    if (state == PW_STREAM_STATE_STREAMING) {
        self->requestCaptureState(true);
    } else if (oldState == PW_STREAM_STATE_STREAMING && (state == PW_STREAM_STATE_PAUSED || state == PW_STREAM_STATE_UNCONNECTED)) {
        self->requestCaptureState(false);
    }
}

void AudioInputStream::Private::pwProcessCallback(void *userdata)
{
    // Real-time PipeWire audio callback: strictly wait-free, zero heap allocations, zero mutexes.
    auto *self = reinterpret_cast<AudioInputStream::Private *>(userdata);
    if (!self || !self->pwStream) {
        return;
    }

    pw_buffer *pwBuf = pw_stream_dequeue_buffer(self->pwStream);
    if (!pwBuf) {
        return;
    }

    if (pwBuf->buffer && pwBuf->buffer->n_datas > 0) {
        spa_data &spaData = pwBuf->buffer->datas[0];
        if (spaData.data && spaData.chunk) {
            const uint32_t frameBytes = static_cast<uint32_t>(self->negotiatedChannels) * sizeof(int16_t);
            const size_t maxFrames = frameBytes > 0 ? (spaData.maxsize / frameBytes) : 0;
            size_t nFrames = (pwBuf->requested > 0) ? static_cast<size_t>(pwBuf->requested) : self->framesPerChunk;
            nFrames = std::min(nFrames, maxFrames);
            const size_t nSamples = nFrames * self->negotiatedChannels;
            auto *dst = static_cast<int16_t *>(spaData.data);

            // Trim excessive buffered mic latency (>60 ms) down to ~20 ms for crisp voice calls.
            const size_t avail = self->ringBuffer.available();
            if (nSamples > 0 && avail > nSamples * 6) {
                self->ringBuffer.discard(avail - nSamples * 2);
            }

            const size_t got = self->ringBuffer.read(dst, nSamples);
            if (got < nSamples) {
                std::memset(dst + got, 0, (nSamples - got) * sizeof(int16_t));
            }

            spaData.chunk->offset = 0;
            spaData.chunk->stride = static_cast<int32_t>(frameBytes);
            spaData.chunk->size = static_cast<uint32_t>(nSamples * sizeof(int16_t));
        }
    }

    pw_stream_queue_buffer(self->pwStream, pwBuf);
}

bool AudioInputStream::Private::ensurePipeWireSourceLocked(uint32_t sampleRate, uint16_t channels)
{
    if (pwStream && negotiatedSampleRate == sampleRate && negotiatedChannels == channels) {
        return true;
    }
    stopPipeWireSourceLocked();

    static std::once_flag pwInitOnce;
    std::call_once(pwInitOnce, []() {
        pw_init(nullptr, nullptr);
    });

    negotiatedSampleRate = sampleRate;
    negotiatedChannels = channels;
    framesPerChunk = std::max<size_t>(160, sampleRate / 100); // ~10 ms
    ringBuffer.configure(framesPerChunk * channels * 12);

    pwLoop = pw_thread_loop_new("krdp-audin", nullptr);
    if (!pwLoop) {
        qCWarning(KRDP) << "AUDIN failed to create PipeWire thread loop";
        return false;
    }
    if (pw_thread_loop_start(pwLoop) < 0) {
        qCWarning(KRDP) << "AUDIN failed to start PipeWire thread loop";
        pw_thread_loop_destroy(pwLoop);
        pwLoop = nullptr;
        return false;
    }

    pwStreamEvents = {};
    pwStreamEvents.version = PW_VERSION_STREAM_EVENTS;
    pwStreamEvents.state_changed = &AudioInputStream::Private::pwStateChangedCallback;
    pwStreamEvents.process = &AudioInputStream::Private::pwProcessCallback;

    char latencySpec[64] = {};
    std::snprintf(latencySpec, sizeof(latencySpec), "%zu/%u", framesPerChunk, sampleRate);
    char maxLatencySpec[64] = {};
    std::snprintf(maxLatencySpec, sizeof(maxLatencySpec), "%zu/%u", framesPerChunk * 2, sampleRate);

    pw_thread_loop_lock(pwLoop);

    pw_properties *props = pw_properties_new(PW_KEY_MEDIA_TYPE,
                                             "Audio",
                                             PW_KEY_MEDIA_CLASS,
                                             "Audio/Source",
                                             PW_KEY_APP_NAME,
                                             "KRDP Server",
                                             PW_KEY_NODE_NAME,
                                             "krdp-audin-source",
                                             PW_KEY_NODE_DESCRIPTION,
                                             "Remote Microphone (RDP)",
                                             PW_KEY_NODE_NICK,
                                             "Remote Microphone",
                                             PW_KEY_DEVICE_CLASS,
                                             "sound",
                                             PW_KEY_DEVICE_FORM_FACTOR,
                                             "microphone",
                                             PW_KEY_DEVICE_ICON_NAME,
                                             "audio-input-microphone",
                                             PW_KEY_NODE_VIRTUAL,
                                             "false",
                                             PW_KEY_PRIORITY_SESSION,
                                             "2000",
                                             PW_KEY_NODE_LATENCY,
                                             latencySpec,
                                             PW_KEY_NODE_MAX_LATENCY,
                                             maxLatencySpec,
                                             nullptr);

    pwStream = pw_stream_new_simple(pw_thread_loop_get_loop(pwLoop), "Remote Microphone (RDP)", props, &pwStreamEvents, this);
    if (!pwStream) {
        pw_thread_loop_unlock(pwLoop);
        qCWarning(KRDP) << "AUDIN failed to create PipeWire Audio/Source stream";
        stopPipeWireSourceLocked();
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

    const auto flags = static_cast<pw_stream_flags>(PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_RT_PROCESS);
    const int rc = pw_stream_connect(pwStream, PW_DIRECTION_OUTPUT, PW_ID_ANY, flags, params, 1);
    pw_thread_loop_unlock(pwLoop);

    if (rc < 0) {
        qCWarning(KRDP) << "AUDIN pw_stream_connect failed:" << rc;
        stopPipeWireSourceLocked();
        return false;
    }

    qCInfo(KRDP) << "AUDIN PipeWire virtual Audio/Source registered:" << sampleRate << "Hz," << channels << "ch";
    return true;
}

void AudioInputStream::Private::stopPipeWireSourceLocked()
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

} // namespace KRdp

#include "moc_AudioInputStream.cpp"
