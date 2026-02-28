/**
 * Channel screen share — encrypted MediaRecorder chunks over Sender Key relay.
 *
 * Architecture (zero-knowledge — server sees nothing):
 * 1. Sharer captures screen via getDisplayMedia()
 * 2. MediaRecorder encodes to VP8/WebM at configurable bitrate in ~100ms chunks
 * 3. Each chunk encrypted with voice_encrypt() (same stable key as voice frames)
 * 4. Sent as `screen_data` messages through the server via Rust backend
 * 5. Server relays raw encrypted bytes (same pattern as voice_data)
 * 6. Recipients decrypt with voice_decrypt()
 * 7. Chunks appended to a MediaSource SourceBuffer → rendered in <video> element
 *
 * Quality presets (all 30fps):
 *   Low:    640x360  / 400 kbps  → ~50 KB/s   (RPi-friendly, modest connections)
 *   Medium: 1280x720 / 1.2 Mbps → ~150 KB/s  (good balance for broadband)
 *   High:   1920x1080/ 2.5 Mbps → ~310 KB/s  (LAN / fast connections)
 *
 * Encryption overhead: 28 bytes/chunk × 10 chunks/s = 280 bytes/s (negligible)
 */

import { invoke } from '@tauri-apps/api/core';
import { get } from 'svelte/store';
import { channelVoiceStore } from './stores/index';
import type { ScreenQuality } from './stores/index';

// ── Quality Presets ──────────────────────────────────────────────────

interface ScreenPreset {
	width: number;
	height: number;
	fps: number;
	bitrate: number;
	/** MediaRecorder timeslice (ms). Longer = bigger chunks but more latency. */
	timeslice: number;
}

const SCREEN_PRESETS: Record<ScreenQuality, ScreenPreset> = {
	low: {
		width: 640,
		height: 360,
		fps: 15,
		bitrate: 400_000,
		timeslice: 250,
	},
	medium: {
		width: 1280,
		height: 720,
		fps: 15,
		bitrate: 1_200_000,
		timeslice: 500,
	},
	high: {
		width: 1920,
		height: 1080,
		fps: 15,
		bitrate: 2_500_000,
		timeslice: 1000,
	},
};

// ── Constants ────────────────────────────────────────────────────────

/** Poll interval for incoming screen chunks */
const SCREEN_POLL_INTERVAL_MS = 50;

/** Maximum pending chunks before we start dropping old ones */
const MAX_PENDING_CHUNKS = 30;

/** Maximum SourceBuffer size in seconds before we trim old data */
const MAX_BUFFER_SECONDS = 15;

// ── Sender (local sharer) state ──────────────────────────────────────

let screenStream: MediaStream | null = null;
let mediaRecorder: MediaRecorder | null = null;
let sendSeq = 0;

// ── Receiver state ───────────────────────────────────────────────────

let screenPollTimer: ReturnType<typeof setInterval> | null = null;
let mediaSource: MediaSource | null = null;
let sourceBuffer: SourceBuffer | null = null;
let videoElement: HTMLVideoElement | null = null;
let pendingChunks: Uint8Array[] = [];
let sbUpdating = false;
/** Set to true once the first chunk is appended (indicates we have the WebM header) */
let hasInitSegment = false;

// ── Public API ───────────────────────────────────────────────────────

/**
 * Start sharing our screen to the current voice channel.
 * Captures the screen, starts MediaRecorder, and sends encrypted chunks.
 *
 * @param quality - 'low' | 'medium' | 'high' (default: 'medium')
 */
export async function startChannelScreenShare(quality: ScreenQuality = 'medium'): Promise<void> {
	const state = get(channelVoiceStore);
	if (!state.channelId) {
		throw new Error('Not in a voice channel');
	}
	if (state.screenSharing) {
		return; // Already sharing
	}

	const preset = SCREEN_PRESETS[quality];

	try {
		screenStream = await navigator.mediaDevices.getDisplayMedia({
			video: {
				frameRate: { ideal: preset.fps, max: preset.fps },
				width: { ideal: preset.width, max: preset.width },
				height: { ideal: preset.height, max: preset.height },
			},
			audio: false,
		});
	} catch (err) {
		console.error('getDisplayMedia failed:', err);
		throw new Error('Screen capture denied or not available');
	}

	// Detect when user clicks "Stop sharing" in the browser's native UI
	const videoTrack = screenStream.getVideoTracks()[0];
	if (videoTrack) {
		videoTrack.onended = () => {
			stopChannelScreenShare();
		};
	}

	sendSeq = 0;

	// Use VP8 WebM if supported, fall back to default
	const mimeType = MediaRecorder.isTypeSupported('video/webm;codecs=vp8')
		? 'video/webm;codecs=vp8'
		: 'video/webm';

	mediaRecorder = new MediaRecorder(screenStream, {
		mimeType,
		videoBitsPerSecond: preset.bitrate,
	});

	mediaRecorder.ondataavailable = async (event: BlobEvent) => {
		if (event.data.size === 0) return;

		const buffer = await event.data.arrayBuffer();
		const chunk = new Uint8Array(buffer);
		const seq = sendSeq++;

		// Send encrypted chunk to Rust backend (which encrypts with Sender Key)
		invoke('send_screen_data', {
			chunk: Array.from(chunk),
			seq,
		}).catch((err) => {
			console.warn('send_screen_data failed:', err);
		});
	};

	mediaRecorder.start(preset.timeslice);

	channelVoiceStore.update(s => ({
		...s,
		screenSharing: true,
		screenQuality: quality,
	}));
	console.log(`[channelScreen] Started screen share (${quality}: ${preset.width}x${preset.height}@${preset.fps}fps, ${preset.bitrate / 1000}kbps)`);
}

/**
 * Stop sharing our screen.
 */
export function stopChannelScreenShare(): void {
	if (mediaRecorder) {
		if (mediaRecorder.state !== 'inactive') {
			mediaRecorder.stop();
		}
		mediaRecorder = null;
	}
	if (screenStream) {
		screenStream.getTracks().forEach(t => t.stop());
		screenStream = null;
	}
	sendSeq = 0;

	channelVoiceStore.update(s => ({
		...s,
		screenSharing: false,
		screenQuality: null,
	}));
	console.log('[channelScreen] Stopped screen share');
}

/**
 * Start polling for incoming screen share chunks.
 * Call this when joining a voice channel.
 */
export function startScreenReceiver(): void {
	if (screenPollTimer) return;
	screenPollTimer = setInterval(pollScreenData, SCREEN_POLL_INTERVAL_MS);
}

/**
 * Stop polling for screen share chunks.
 * Call this when leaving a voice channel.
 */
export function stopScreenReceiver(): void {
	if (screenPollTimer) {
		clearInterval(screenPollTimer);
		screenPollTimer = null;
	}
	cleanupReceiver();
}

/**
 * Bind a <video> element for rendering received screen share content.
 * Should be called when the video element is mounted in the DOM.
 */
export function bindScreenVideo(el: HTMLVideoElement | null): void {
	if (!el) {
		// Don't cleanup receiver on unbind — just detach the element ref.
		// The receiver keeps running so we don't lose the stream.
		videoElement = null;
		return;
	}
	videoElement = el;
	// If we already have a MediaSource with a valid object URL, re-attach.
	if (mediaSource && mediaSource.readyState === 'open') {
		el.src = URL.createObjectURL(mediaSource);
		el.play().catch(() => {});
	}
}

// ── Polling ──────────────────────────────────────────────────────────

async function pollScreenData(): Promise<void> {
	try {
		const data: [string, number[], number][] = await invoke('poll_screen_data');
		if (!data || data.length === 0) return;

		for (const [senderHex, chunkBytes, _seq] of data) {
			const chunk = new Uint8Array(chunkBytes);

			// Update store with who is sharing
			channelVoiceStore.update(s => {
				if (s.remoteScreenSharer !== senderHex) {
					return { ...s, remoteScreenSharer: senderHex };
				}
				return s;
			});

			// Initialize MediaSource on first chunk
			if (!mediaSource && videoElement) {
				initMediaSource();
			}

			// Queue chunk for appending to SourceBuffer
			if (pendingChunks.length < MAX_PENDING_CHUNKS) {
				pendingChunks.push(chunk);
			} else {
				// Drop oldest non-init chunks to prevent unbounded growth.
				// Never drop the first chunk (index 0) if we haven't init'd yet.
				if (hasInitSegment) {
					pendingChunks.shift();
				}
				pendingChunks.push(chunk);
			}
			flushPendingChunks();
		}
	} catch (err) {
		console.warn('poll_screen_data error:', err);
	}
}

// ── MediaSource management ───────────────────────────────────────────

function initMediaSource(): void {
	if (!videoElement) return;

	// Clean up any prior MediaSource
	if (mediaSource) {
		try {
			if (mediaSource.readyState === 'open') {
				mediaSource.endOfStream();
			}
		} catch { /* ignore */ }
	}
	sourceBuffer = null;
	sbUpdating = false;
	hasInitSegment = false;

	mediaSource = new MediaSource();
	videoElement.src = URL.createObjectURL(mediaSource);

	mediaSource.addEventListener('sourceopen', () => {
		if (!mediaSource) return;

		// Use VP8 codec matching what MediaRecorder produces
		const mimeType = 'video/webm;codecs=vp8';
		try {
			sourceBuffer = mediaSource.addSourceBuffer(mimeType);
			sourceBuffer.mode = 'sequence';
			sourceBuffer.addEventListener('updateend', onSourceBufferUpdateEnd);

			// Start playback
			if (videoElement) {
				videoElement.play().catch(() => {
					// Autoplay might be blocked; user interaction will be needed
					console.warn('[channelScreen] Autoplay blocked — user interaction needed');
				});
			}

			// Flush any chunks that arrived before sourceopen
			flushPendingChunks();
		} catch (e) {
			console.error('[channelScreen] Failed to create SourceBuffer:', e);
		}
	});
}

function onSourceBufferUpdateEnd(): void {
	sbUpdating = false;

	// Trim old data to prevent the buffer from growing indefinitely
	trimBuffer();

	// Continue flushing remaining pending chunks
	flushPendingChunks();
}

function trimBuffer(): void {
	if (!sourceBuffer || sourceBuffer.updating || !videoElement) return;

	try {
		const buffered = sourceBuffer.buffered;
		if (buffered.length > 0) {
			const bufferEnd = buffered.end(buffered.length - 1);
			const currentTime = videoElement.currentTime;

			// Keep video time near the live edge to prevent latency buildup
			if (bufferEnd - currentTime > 3) {
				videoElement.currentTime = bufferEnd - 0.5;
			}

			// Remove data older than MAX_BUFFER_SECONDS behind current time
			const removeEnd = currentTime - MAX_BUFFER_SECONDS;
			if (removeEnd > 0 && buffered.start(0) < removeEnd) {
				sourceBuffer.remove(buffered.start(0), removeEnd);
			}
		}
	} catch {
		// Ignore — buffer operations can throw if source is closed
	}
}

function flushPendingChunks(): void {
	if (sbUpdating || !sourceBuffer || sourceBuffer.updating || pendingChunks.length === 0) {
		return;
	}

	// Concatenate all pending chunks into a single buffer for efficiency.
	// This reduces the number of appendBuffer calls (each triggers an async update cycle).
	let chunk: Uint8Array;
	if (pendingChunks.length === 1) {
		chunk = pendingChunks.shift()!;
	} else {
		const totalLen = pendingChunks.reduce((sum, c) => sum + c.length, 0);
		chunk = new Uint8Array(totalLen);
		let offset = 0;
		for (const c of pendingChunks) {
			chunk.set(c, offset);
			offset += c.length;
		}
		pendingChunks = [];
	}

	try {
		sbUpdating = true;
		sourceBuffer.appendBuffer(chunk);
		if (!hasInitSegment) {
			hasInitSegment = true;
		}
	} catch (e) {
		sbUpdating = false;
		console.warn('[channelScreen] appendBuffer error:', e);
		// If quota exceeded, try to clear buffer and retry
		if (e instanceof DOMException && e.name === 'QuotaExceededError') {
			try {
				if (videoElement && !sourceBuffer.updating) {
					sourceBuffer.remove(0, videoElement.currentTime - 1);
				}
			} catch {
				// ignore
			}
		}
	}
}

function cleanupReceiver(): void {
	pendingChunks = [];
	sbUpdating = false;
	hasInitSegment = false;

	if (sourceBuffer) {
		try {
			sourceBuffer.removeEventListener('updateend', onSourceBufferUpdateEnd);
			if (mediaSource && mediaSource.readyState === 'open') {
				mediaSource.removeSourceBuffer(sourceBuffer);
			}
		} catch {
			// ignore
		}
		sourceBuffer = null;
	}

	if (mediaSource) {
		if (mediaSource.readyState === 'open') {
			try {
				mediaSource.endOfStream();
			} catch {
				// ignore
			}
		}
		mediaSource = null;
	}

	if (videoElement) {
		videoElement.src = '';
		videoElement = null;
	}

	channelVoiceStore.update(s => ({ ...s, remoteScreenSharer: null }));
}

/**
 * Reset the receiver pipeline (e.g. when the sharer changes quality or restarts).
 * Tears down the current MediaSource so the next incoming chunk will reinit it.
 */
export function resetScreenReceiver(): void {
	pendingChunks = [];
	sbUpdating = false;
	hasInitSegment = false;

	if (sourceBuffer) {
		try {
			sourceBuffer.removeEventListener('updateend', onSourceBufferUpdateEnd);
			if (mediaSource && mediaSource.readyState === 'open') {
				mediaSource.removeSourceBuffer(sourceBuffer);
			}
		} catch { /* ignore */ }
		sourceBuffer = null;
	}

	if (mediaSource) {
		try {
			if (mediaSource.readyState === 'open') {
				mediaSource.endOfStream();
			}
		} catch { /* ignore */ }
		mediaSource = null;
	}

	// Don't null videoElement — it stays bound. Next incoming chunk will reinit.
}

/**
 * Cleanup everything — called when leaving voice channel.
 */
export function cleanupChannelScreen(): void {
	stopChannelScreenShare();
	stopScreenReceiver();
}
