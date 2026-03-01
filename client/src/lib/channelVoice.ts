/**
 * Channel voice chat — Opus 24kbps codec with Sender Key encryption.
 *
 * Architecture:
 * - Audio captured via getUserMedia → ScriptProcessorNode (960 samples = 20ms at 48kHz)
 * - Opus encoded at 24kbps VBR, mono, voip mode → ~30-60 byte packets per 20ms frame
 * - Sent to Rust backend via invoke('send_voice_data') which encrypts with AES-256-GCM
 *   (Sender Key ratchet, 28 bytes overhead) before relaying to server
 * - Server relays opaque encrypted bytes to other participants
 * - Rust backend decrypts incoming frames, frontend decodes Opus → PCM → playback
 *
 * Opus DTX (Discontinuous Transmission) handles VAD automatically:
 * the encoder emits tiny "comfort noise" frames during silence instead of
 * full-rate frames, so no manual VAD threshold is needed.
 *
 * Bandwidth: ~3-5 KB/s per active speaker (incl. encryption overhead)
 * Quality: 48kHz wideband, perceptual coding — good voice clarity at minimal bitrate
 */

import { invoke } from '@tauri-apps/api/core';
import { get } from 'svelte/store';
import { channelVoiceStore } from './stores/index';
import { startScreenReceiver, stopScreenReceiver, cleanupChannelScreen } from './channelScreen';

// Import Opus encoder/decoder from the self-contained deno.js entry
// (WASM binary is embedded inline — no FS or network required)
// @ts-ignore — no type declarations for this sub-path
import { Encoder as OpusEncoder, Decoder as OpusDecoder } from '@evan/wasm/target/opus/deno.js';

// ── Constants ────────────────────────────────────────────────────────

const SAMPLE_RATE = 48000; // Opus native sample rate
const CHANNELS = 1; // Mono
const FRAME_SIZE = 960; // 20ms at 48kHz (960 samples)
const OPUS_BITRATE = 24000; // 24 kbps — good voice clarity, minimal bandwidth
const POLL_INTERVAL_MS = 20; // Audio data poll interval
const EVENT_POLL_INTERVAL_MS = 250; // Voice event poll interval
const JITTER_BUFFER_MAX = 10; // Max buffered frames per speaker (~200ms)

// ── State ────────────────────────────────────────────────────────────

let audioContext: AudioContext | null = null;
let mediaStream: MediaStream | null = null;
let captureNode: ScriptProcessorNode | null = null;
let playbackNode: ScriptProcessorNode | null = null;
let opusEncoder: InstanceType<typeof OpusEncoder> | null = null;
let sendSeq = 0;
let captureBuffer: Float32Array = new Float32Array(0);
let dataPollTimer: ReturnType<typeof setInterval> | null = null;
let eventPollTimer: ReturnType<typeof setInterval> | null = null;
let isMuted = false;

// Per-speaker state: Opus decoder + jitter buffer of decoded PCM frames
interface SpeakerState {
	decoder: InstanceType<typeof OpusDecoder>;
	frames: Float32Array[];
}
const speakers = new Map<string, SpeakerState>();

// ── Public API ───────────────────────────────────────────────────────

export async function joinVoice(channelId: string): Promise<void> {
	const current = get(channelVoiceStore);
	if (current.channelId) {
		await leaveVoice();
	}

	// Join on the Rust side (sends join_voice to server)
	await invoke('join_voice_channel', { channelId });

	// Initialize audio context at 48kHz (Opus native rate — no resampling needed)
	audioContext = new AudioContext({ sampleRate: SAMPLE_RATE });

	try {
		if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
			throw new Error(
				'Microphone access is not available in this environment. ' +
				'On Linux, ensure PipeWire or PulseAudio is running.'
			);
		}
		// Try with full constraints first
		try {
			mediaStream = await navigator.mediaDevices.getUserMedia({
				audio: {
					echoCancellation: true,
					noiseSuppression: true,
					autoGainControl: true,
					sampleRate: SAMPLE_RATE,
				},
				video: false,
			});
		} catch {
			console.warn('[channelVoice] Full constraints failed, trying basic audio');
			mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
		}
	} catch (err) {
		console.error('Failed to get audio input:', err);
		await invoke('leave_voice_channel');
		const msg = err instanceof Error ? err.message : 'Microphone access denied';
		throw new Error(msg);
	}

	// Create Opus encoder
	opusEncoder = new OpusEncoder({
		channels: CHANNELS,
		sample_rate: SAMPLE_RATE,
		application: 'voip',
	});
	opusEncoder.bitrate = OPUS_BITRATE;
	opusEncoder.signal = 'voice';
	opusEncoder.dtx = true; // Discontinuous transmission — built-in VAD
	opusEncoder.complexity = 3; // Low CPU — good enough for voice at 24kbps
	opusEncoder.vbr = true;

	// Capture pipeline: mic → ScriptProcessorNode → Opus encode → send
	const source = audioContext.createMediaStreamSource(mediaStream);
	// Buffer size 960 = exactly one 20ms Opus frame at 48kHz.
	// ScriptProcessorNode requires power-of-2 buffer sizes, so use 1024
	// and accumulate samples to emit exact 960-sample frames.
	captureNode = audioContext.createScriptProcessor(1024, 1, 1);
	captureNode.onaudioprocess = onCaptureProcess;
	source.connect(captureNode);
	captureNode.connect(audioContext.destination);

	// Playback pipeline: decode → mix → ScriptProcessorNode → speakers
	playbackNode = audioContext.createScriptProcessor(1024, 1, 1);
	playbackNode.onaudioprocess = onPlaybackProcess;
	playbackNode.connect(audioContext.destination);

	sendSeq = 0;
	captureBuffer = new Float32Array(0);
	isMuted = false;
	speakers.clear();

	dataPollTimer = setInterval(pollVoiceData, POLL_INTERVAL_MS);
	eventPollTimer = setInterval(pollVoiceEvents, EVENT_POLL_INTERVAL_MS);

	// Start polling for incoming screen share data
	startScreenReceiver();

	channelVoiceStore.set({
		channelId,
		participants: [],
		muted: false,
		screenSharing: false,
		screenQuality: null,
		remoteScreenSharer: null,
	});
}

export async function leaveVoice(): Promise<void> {
	// Stop screen share if active
	cleanupChannelScreen();

	if (dataPollTimer) { clearInterval(dataPollTimer); dataPollTimer = null; }
	if (eventPollTimer) { clearInterval(eventPollTimer); eventPollTimer = null; }

	if (captureNode) {
		captureNode.disconnect();
		captureNode.onaudioprocess = null;
		captureNode = null;
	}
	if (playbackNode) {
		playbackNode.disconnect();
		playbackNode.onaudioprocess = null;
		playbackNode = null;
	}
	if (mediaStream) {
		mediaStream.getTracks().forEach(t => t.stop());
		mediaStream = null;
	}
	if (audioContext) {
		await audioContext.close().catch(() => {});
		audioContext = null;
	}

	// Clean up Opus encoder/decoders
	if (opusEncoder) {
		// Encoder doesn't have explicit drop in JS, GC will handle it
		opusEncoder = null;
	}
	for (const [, state] of speakers) {
		// Decoders also GC'd
		state.frames.length = 0;
	}
	speakers.clear();

	await invoke('leave_voice_channel').catch(() => {});

	channelVoiceStore.set({
		channelId: null,
		participants: [],
		muted: false,
		screenSharing: false,
		screenQuality: null,
		remoteScreenSharer: null,
	});
}

export function toggleVoiceMute(): void {
	isMuted = !isMuted;
	if (mediaStream) {
		mediaStream.getAudioTracks().forEach(t => { t.enabled = !isMuted; });
	}
	channelVoiceStore.update(s => ({ ...s, muted: isMuted }));
}

// ── Audio capture ────────────────────────────────────────────────────

function onCaptureProcess(e: AudioProcessingEvent): void {
	if (isMuted || !opusEncoder) return;

	const input = e.inputBuffer.getChannelData(0);

	// Accumulate samples (ScriptProcessor gives 1024, Opus wants 960)
	const combined = new Float32Array(captureBuffer.length + input.length);
	combined.set(captureBuffer);
	combined.set(input, captureBuffer.length);

	let offset = 0;
	while (offset + FRAME_SIZE <= combined.length) {
		const frame = combined.subarray(offset, offset + FRAME_SIZE);
		offset += FRAME_SIZE;

		// Convert Float32 [-1, 1] to Int16 PCM for Opus encoder
		const pcm16 = new Int16Array(FRAME_SIZE);
		for (let i = 0; i < FRAME_SIZE; i++) {
			pcm16[i] = Math.max(-32768, Math.min(32767, Math.round(frame[i] * 32767)));
		}

		// Opus encode → variable-length packet (Uint8Array)
		const packet: Uint8Array = opusEncoder.encode(pcm16);

		// DTX: Opus may emit very small packets (<=2 bytes) for silence.
		// Skip sending these — the decoder handles missing frames gracefully.
		if (packet.length <= 2) {
			sendSeq++;
			continue;
		}

		// Send to Rust backend (which encrypts with Sender Key before relaying)
		const seq = sendSeq++;
		invoke('send_voice_data', {
			audio: Array.from(packet),
			seq,
		}).catch(err => {
			console.warn('send_voice_data failed:', err);
		});
	}

	// Keep remaining samples for next callback
	captureBuffer = combined.slice(offset);
}

// ── Audio playback ───────────────────────────────────────────────────

function onPlaybackProcess(e: AudioProcessingEvent): void {
	const output = e.outputBuffer.getChannelData(0);
	const outputLen = output.length; // 1024 at 48kHz

	output.fill(0);

	// Mix all speakers' decoded PCM
	for (const [, state] of speakers) {
		if (state.frames.length === 0) continue;

		let outputIdx = 0;
		while (outputIdx < outputLen && state.frames.length > 0) {
			const frame = state.frames[0];
			const remaining = outputLen - outputIdx;
			const toCopy = Math.min(frame.length, remaining);

			for (let i = 0; i < toCopy; i++) {
				output[outputIdx + i] += frame[i];
			}
			outputIdx += toCopy;

			if (toCopy >= frame.length) {
				// Consumed entire frame
				state.frames.shift();
			} else {
				// Partially consumed — keep remainder
				state.frames[0] = frame.subarray(toCopy);
			}
		}
	}

	// Clamp mixed output
	for (let i = 0; i < outputLen; i++) {
		if (output[i] > 1) output[i] = 1;
		else if (output[i] < -1) output[i] = -1;
	}
}

// ── Polling ──────────────────────────────────────────────────────────

async function pollVoiceData(): Promise<void> {
	try {
		const data: [string, number[], number][] = await invoke('poll_voice_data');
		if (!data || data.length === 0) return;

		for (const [senderHex, opusBytes, _seq] of data) {
			// Get or create per-speaker decoder
			let state = speakers.get(senderHex);
			if (!state) {
				state = {
					decoder: new OpusDecoder({
						channels: CHANNELS,
						sample_rate: SAMPLE_RATE,
					}),
					frames: [],
				};
				speakers.set(senderHex, state);
			}

			// Opus decode → PCM Int16 → Float32
			const packet = new Uint8Array(opusBytes);
			const decoded: Uint8Array = state.decoder.decode(packet);

			// decoded is Int16 PCM as Uint8Array (little-endian)
			const pcm16 = new Int16Array(decoded.buffer, decoded.byteOffset, decoded.byteLength / 2);
			const pcmFloat = new Float32Array(pcm16.length);
			for (let i = 0; i < pcm16.length; i++) {
				pcmFloat[i] = pcm16[i] / 32768;
			}

			state.frames.push(pcmFloat);

			// Cap jitter buffer
			while (state.frames.length > JITTER_BUFFER_MAX) {
				state.frames.shift();
			}
		}
	} catch (err) {
		console.warn('poll_voice_data error:', err);
	}
}

async function pollVoiceEvents(): Promise<void> {
	try {
		const events: string[] = await invoke('poll_voice_events');
		if (!events || events.length === 0) return;

		for (const eventJson of events) {
			const event = JSON.parse(eventJson);

			switch (event.type) {
				case 'voice_state':
					channelVoiceStore.update(s => ({
						...s,
						participants: event.participants || [],
					}));
					break;

				case 'voice_joined':
					if (event.pubkey) {
						channelVoiceStore.update(s => ({
							...s,
							participants: s.participants.includes(event.pubkey)
								? s.participants
								: [...s.participants, event.pubkey],
						}));
					}
					break;

				case 'voice_left':
					if (event.pubkey) {
						channelVoiceStore.update(s => ({
							...s,
							participants: s.participants.filter((p: string) => p !== event.pubkey),
						}));
						// Clean up speaker state
						const state = speakers.get(event.pubkey);
						if (state) {
							state.frames.length = 0;
							speakers.delete(event.pubkey);
						}
					}
					break;
			}
		}
	} catch (err) {
		console.warn('poll_voice_events error:', err);
	}
}
