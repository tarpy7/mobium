/**
 * Voice Call Manager
 *
 * Handles WebRTC peer-to-peer voice calls with end-to-end encryption.
 *
 * Architecture:
 * - Signaling goes through the existing Mobium server (voice_signal messages)
 * - Media (audio) goes peer-to-peer via WebRTC with DTLS-SRTP encryption
 * - The server never sees or relays audio data, only opaque signaling blobs
 * - ICE candidates are gathered via STUN to enable NAT traversal
 *
 * Flow:
 *   Caller: startCall(peerPubkey)
 *     -> getUserMedia() -> createOffer() -> send voice_signal(offer)
 *   Callee: receives voice_signal(offer) event
 *     -> acceptCall() -> createAnswer() -> send voice_signal(answer)
 *   Both: exchange ICE candidates via voice_signal(ice_candidate)
 *   Either: endCall() -> send voice_signal(hangup)
 */

import { invoke } from '@tauri-apps/api/core';
import { get } from 'svelte/store';
import { voiceCallStore, displayName, addToast, type VoiceCallState } from '$lib/stores';

// STUN servers for NAT traversal (public, no credentials needed)
const ICE_SERVERS: RTCConfiguration = {
	iceServers: [
		{ urls: 'stun:stun.l.google.com:19302' },
		{ urls: 'stun:stun1.l.google.com:19302' },
	],
};

let peerConnection: RTCPeerConnection | null = null;
let localStream: MediaStream | null = null;
let screenStream: MediaStream | null = null;
let remoteAudio: HTMLAudioElement | null = null;
let remoteVideo: HTMLVideoElement | null = null;
let screenSender: RTCRtpSender | null = null;
/** Stores the remote video stream until the <video> element is bound */
let pendingRemoteStream: MediaStream | null = null;

// Pending offer from an incoming call (before user accepts)
let pendingOffer: RTCSessionDescriptionInit | null = null;
let pendingCandidates: RTCIceCandidateInit[] = [];

// ── Ringtone (Web Audio API) ────────────────────────────────────────
// Generates a classic two-tone ring pattern: 440Hz+480Hz for 1s, silence 2s, repeat.
let ringtoneCtx: AudioContext | null = null;
let ringtoneInterval: ReturnType<typeof setInterval> | null = null;
let ringtoneTimeout: ReturnType<typeof setTimeout> | null = null;

function startRingtone() {
	stopRingtone();
	try {
		ringtoneCtx = new AudioContext();
		playRingBurst(); // play immediately
		ringtoneInterval = setInterval(playRingBurst, 3000); // repeat every 3s
		// Auto-stop after 30s (missed call)
		ringtoneTimeout = setTimeout(() => {
			const state = get(voiceCallStore);
			if (state.state === 'ringing_in') {
				rejectCall(); // auto-reject after 30s unanswered
			}
		}, 30_000);
	} catch {
		// Web Audio not available — silent fallback
	}
}

function playRingBurst() {
	if (!ringtoneCtx) return;
	const now = ringtoneCtx.currentTime;
	const gain = ringtoneCtx.createGain();
	gain.connect(ringtoneCtx.destination);
	gain.gain.setValueAtTime(0.15, now);
	gain.gain.setValueAtTime(0, now + 0.8); // 800ms burst

	// Two-tone: 440Hz + 480Hz (US ring cadence)
	for (const freq of [440, 480]) {
		const osc = ringtoneCtx.createOscillator();
		osc.type = 'sine';
		osc.frequency.setValueAtTime(freq, now);
		osc.connect(gain);
		osc.start(now);
		osc.stop(now + 0.8);
	}
}

function stopRingtone() {
	if (ringtoneInterval) {
		clearInterval(ringtoneInterval);
		ringtoneInterval = null;
	}
	if (ringtoneTimeout) {
		clearTimeout(ringtoneTimeout);
		ringtoneTimeout = null;
	}
	if (ringtoneCtx) {
		ringtoneCtx.close().catch(() => {});
		ringtoneCtx = null;
	}
}

// ── Outgoing ring-back tone ─────────────────────────────────────────
let ringbackCtx: AudioContext | null = null;
let ringbackInterval: ReturnType<typeof setInterval> | null = null;

function startRingback() {
	stopRingback();
	try {
		ringbackCtx = new AudioContext();
		playRingbackBurst();
		ringbackInterval = setInterval(playRingbackBurst, 4000);
	} catch {
		// silent fallback
	}
}

function playRingbackBurst() {
	if (!ringbackCtx) return;
	const now = ringbackCtx.currentTime;
	const gain = ringbackCtx.createGain();
	gain.connect(ringbackCtx.destination);
	gain.gain.setValueAtTime(0.08, now);
	gain.gain.setValueAtTime(0, now + 1.0);

	// Single softer tone at 440Hz (classic ring-back)
	const osc = ringbackCtx.createOscillator();
	osc.type = 'sine';
	osc.frequency.setValueAtTime(440, now);
	osc.connect(gain);
	osc.start(now);
	osc.stop(now + 1.0);
}

function stopRingback() {
	if (ringbackInterval) {
		clearInterval(ringbackInterval);
		ringbackInterval = null;
	}
	if (ringbackCtx) {
		ringbackCtx.close().catch(() => {});
		ringbackCtx = null;
	}
}

function updateState(partial: Partial<import('$lib/stores').VoiceCall>) {
	voiceCallStore.update(s => ({ ...s, ...partial }));
}

function cleanup() {
	stopRingtone();
	stopRingback();
	if (peerConnection) {
		peerConnection.close();
		peerConnection = null;
	}
	if (localStream) {
		localStream.getTracks().forEach(t => t.stop());
		localStream = null;
	}
	if (screenStream) {
		screenStream.getTracks().forEach(t => t.stop());
		screenStream = null;
	}
	screenSender = null;
	if (remoteAudio) {
		remoteAudio.srcObject = null;
	}
	if (remoteVideo) {
		remoteVideo.srcObject = null;
	}
	pendingRemoteStream = null;
	pendingOffer = null;
	pendingCandidates = [];
}

/**
 * Start an outgoing voice call to a peer.
 */
export async function startCall(peerPubkey: string): Promise<void> {
	const currentState = get(voiceCallStore);
	if (currentState.state !== 'idle') {
		throw new Error(`Cannot start call: already in state '${currentState.state}'`);
	}

	// Drain any stale voice signals left from a previous call attempt.
	// Without this, a lingering reject/hangup in the buffer would cause
	// the new call to be "immediately rejected".
	try {
		await invoke('clear_voice_signals');
	} catch {
		// Not fatal — best effort
	}

	updateState({ state: 'ringing_out', peerPubkey, error: null });
	startRingback();

	try {
		// Get microphone access
		localStream = await navigator.mediaDevices.getUserMedia({
			audio: {
				echoCancellation: true,
				noiseSuppression: true,
				autoGainControl: true,
			},
			video: false,
		});

		// Create peer connection
		peerConnection = new RTCPeerConnection(ICE_SERVERS);
		setupPeerConnectionHandlers(peerPubkey);

		// Add local audio tracks to the connection
		for (const track of localStream.getAudioTracks()) {
			peerConnection.addTrack(track, localStream);
		}

		// Create and send offer
		const offer = await peerConnection.createOffer();
		await peerConnection.setLocalDescription(offer);

		const offerPayload = new TextEncoder().encode(JSON.stringify(offer));
		await invoke('send_voice_signal', {
			recipient: peerPubkey,
			signalType: 'offer',
			payload: Array.from(offerPayload),
		});

		console.log('[voice] Sent offer to', peerPubkey.substring(0, 16));
	} catch (e: unknown) {
		const msg = e instanceof Error ? e.message : String(e);
		console.error('[voice] startCall failed:', msg);
		cleanup();
		updateState({ state: 'ended', error: msg });
		// Auto-reset to idle after showing error
		setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 3000);
		throw e;
	}
}

/**
 * Accept an incoming voice call.
 */
export async function acceptCall(): Promise<void> {
	const currentState = get(voiceCallStore);
	if (currentState.state !== 'ringing_in' || !currentState.peerPubkey || !pendingOffer) {
		throw new Error('No incoming call to accept');
	}

	const peerPubkey = currentState.peerPubkey;
	stopRingtone();
	updateState({ state: 'connecting' });

	try {
		// Get microphone access
		localStream = await navigator.mediaDevices.getUserMedia({
			audio: {
				echoCancellation: true,
				noiseSuppression: true,
				autoGainControl: true,
			},
			video: false,
		});

		// Create peer connection
		peerConnection = new RTCPeerConnection(ICE_SERVERS);
		setupPeerConnectionHandlers(peerPubkey);

		// Add local audio tracks
		for (const track of localStream.getAudioTracks()) {
			peerConnection.addTrack(track, localStream);
		}

		// Set the remote offer
		await peerConnection.setRemoteDescription(new RTCSessionDescription(pendingOffer));
		pendingOffer = null;

		// Process any ICE candidates that arrived before we accepted
		for (const candidate of pendingCandidates) {
			await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
		}
		pendingCandidates = [];

		// Create and send answer
		const answer = await peerConnection.createAnswer();
		await peerConnection.setLocalDescription(answer);

		const answerPayload = new TextEncoder().encode(JSON.stringify(answer));
		await invoke('send_voice_signal', {
			recipient: peerPubkey,
			signalType: 'answer',
			payload: Array.from(answerPayload),
		});

		console.log('[voice] Sent answer to', peerPubkey.substring(0, 16));
	} catch (e: unknown) {
		const msg = e instanceof Error ? e.message : String(e);
		console.error('[voice] acceptCall failed:', msg);
		updateState({ state: 'ended', error: msg });
		cleanup();
		setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 3000);
		throw e;
	}
}

/**
 * Reject an incoming call.
 */
export async function rejectCall(): Promise<void> {
	const currentState = get(voiceCallStore);
	if (currentState.state !== 'ringing_in' || !currentState.peerPubkey) {
		return;
	}

	stopRingtone();

	await invoke('send_voice_signal', {
		recipient: currentState.peerPubkey,
		signalType: 'reject',
		payload: [],
	});

	pendingOffer = null;
	pendingCandidates = [];
	updateState({ state: 'idle', peerPubkey: null, error: null });

	// Drain stale signals so the next call starts clean
	try {
		await invoke('clear_voice_signals');
	} catch {
		// Not fatal
	}
}

/**
 * End the current call (hang up).
 */
export async function endCall(): Promise<void> {
	const currentState = get(voiceCallStore);
	if (currentState.peerPubkey && currentState.state !== 'idle') {
		try {
			await invoke('send_voice_signal', {
				recipient: currentState.peerPubkey,
				signalType: 'hangup',
				payload: [],
			});
		} catch {
			// Best effort
		}
	}

	cleanup();
	updateState({ state: 'idle', peerPubkey: null, startTime: null, muted: false, error: null, screenSharing: false, remoteScreenSharing: false });

	// Drain stale signals so the next call starts clean
	try {
		await invoke('clear_voice_signals');
	} catch {
		// Not fatal
	}
}

/**
 * Toggle microphone mute.
 */
export function toggleMute(): void {
	if (!localStream) return;
	const tracks = localStream.getAudioTracks();
	const currentState = get(voiceCallStore);
	const newMuted = !currentState.muted;

	for (const track of tracks) {
		track.enabled = !newMuted;
	}
	updateState({ muted: newMuted });
}

/**
 * Start sharing your screen during an active DM call.
 *
 * Captures the screen via getDisplayMedia() and adds the video track to
 * the existing peer connection. The video goes peer-to-peer via WebRTC
 * (DTLS-SRTP encrypted) — the server never sees it.
 */
export async function startScreenShare(): Promise<void> {
	const currentState = get(voiceCallStore);
	if (currentState.state !== 'active' || !peerConnection) {
		throw new Error('Must be in an active call to share screen');
	}

	try {
		screenStream = await navigator.mediaDevices.getDisplayMedia({
			video: {
				// Low bitrate for RPi relay efficiency; resolution capped for bandwidth
				width: { ideal: 1280, max: 1920 },
				height: { ideal: 720, max: 1080 },
				frameRate: { ideal: 15, max: 30 },
			},
			audio: false,
		});

		const videoTrack = screenStream.getVideoTracks()[0];
		if (!videoTrack) {
			throw new Error('No video track from getDisplayMedia');
		}

		// When the user clicks the browser's "Stop sharing" button
		videoTrack.onended = () => {
			stopScreenShare();
		};

		// Add the video track to the peer connection
		screenSender = peerConnection.addTrack(videoTrack, screenStream);

		// Notify the other peer via renegotiation (new offer)
		const offer = await peerConnection.createOffer();
		await peerConnection.setLocalDescription(offer);
		const offerPayload = new TextEncoder().encode(JSON.stringify(offer));
		await invoke('send_voice_signal', {
			recipient: currentState.peerPubkey!,
			signalType: 'offer',
			payload: Array.from(offerPayload),
		});

		updateState({ screenSharing: true });
		console.log('[voice] Screen share started');
	} catch (e: unknown) {
		// User cancelled the picker or browser denied access
		if (screenStream) {
			screenStream.getTracks().forEach(t => t.stop());
			screenStream = null;
		}
		screenSender = null;
		const msg = e instanceof Error ? e.message : String(e);
		if (!msg.includes('Permission denied') && !msg.includes('AbortError')) {
			console.error('[voice] Screen share failed:', msg);
		}
	}
}

/**
 * Stop sharing your screen.
 */
export function stopScreenShare(): void {
	if (screenSender && peerConnection) {
		peerConnection.removeTrack(screenSender);
		screenSender = null;
	}
	if (screenStream) {
		screenStream.getTracks().forEach(t => t.stop());
		screenStream = null;
	}
	updateState({ screenSharing: false });

	// Renegotiate to inform peer the track is gone
	if (peerConnection && get(voiceCallStore).peerPubkey) {
		peerConnection.createOffer().then(async (offer) => {
			await peerConnection!.setLocalDescription(offer);
			const offerPayload = new TextEncoder().encode(JSON.stringify(offer));
			await invoke('send_voice_signal', {
				recipient: get(voiceCallStore).peerPubkey!,
				signalType: 'offer',
				payload: Array.from(offerPayload),
			});
		}).catch(e => console.warn('[voice] Renegotiation after screen stop failed:', e));
	}

	console.log('[voice] Screen share stopped');
}

/**
 * Bind the <video> element used to display remote screen share.
 * Called from VoiceCall.svelte when the video element mounts/unmounts.
 *
 * If a remote video stream arrived before the element was bound (common
 * because the element is conditionally rendered based on remoteScreenSharing),
 * it is attached here.
 */
export function bindRemoteVideo(el: HTMLVideoElement | null): void {
	remoteVideo = el;
	if (el && pendingRemoteStream) {
		console.log('[voice] Attaching pending remote stream to video element');
		el.srcObject = pendingRemoteStream;
		// Mute to allow autoplay (video content — audio is separate)
		el.muted = true;
		el.play().catch(() => {
			console.warn('[voice] Autoplay blocked on remote video');
		});
	} else if (el && !pendingRemoteStream) {
		// Element bound but no stream yet — ensure it's ready for when stream arrives
		el.muted = true;
	}
}

/**
 * Handle an incoming voice signal from the server.
 * Called by the event system when a 'voice_signal' Tauri event arrives.
 */
export async function handleVoiceSignal(
	sender: string,
	signalType: string,
	payload: number[],
): Promise<void> {
	const payloadStr = new TextDecoder().decode(new Uint8Array(payload));
	const currentState = get(voiceCallStore);

	console.log('[voice] handleVoiceSignal:', signalType, 'from', sender.substring(0, 16), 'state:', currentState.state);

	switch (signalType) {
		case 'offer': {
			// Renegotiation: if we're already in a call with this peer,
			// handle as a renegotiation (e.g. screen share added/removed).
			if (
				peerConnection &&
				currentState.peerPubkey === sender &&
				(currentState.state === 'active' || currentState.state === 'connecting')
			) {
				console.log('[voice] Renegotiation offer from peer (screen share change)');
				const reOffer = JSON.parse(payloadStr) as RTCSessionDescriptionInit;
				await peerConnection.setRemoteDescription(new RTCSessionDescription(reOffer));
				const answer = await peerConnection.createAnswer();
				await peerConnection.setLocalDescription(answer);
				const answerPayload = new TextEncoder().encode(JSON.stringify(answer));
				await invoke('send_voice_signal', {
					recipient: sender,
					signalType: 'answer',
					payload: Array.from(answerPayload),
				});
				break;
			}

			// New incoming call
			if (currentState.state !== 'idle') {
				// Already in a call with someone else — auto-reject
				await invoke('send_voice_signal', {
					recipient: sender,
					signalType: 'reject',
					payload: [],
				});
				return;
			}

			const offer = JSON.parse(payloadStr) as RTCSessionDescriptionInit;
			pendingOffer = offer;
			pendingCandidates = [];
			updateState({ state: 'ringing_in', peerPubkey: sender, error: null });

			// Play ringtone so the user hears the incoming call
			startRingtone();

			// Desktop notification (persists even if app window is not focused)
			if ('Notification' in window && Notification.permission === 'granted') {
				const notif = new Notification('Incoming Voice Call', {
					body: `${displayName(sender)} is calling...`,
					icon: '/favicon.png',
					requireInteraction: true, // stays until dismissed
					tag: 'voice-call', // replaces previous call notification
				});
				notif.onclick = () => {
					window.focus();
					notif.close();
				};
			}

			// In-app toast (supplementary)
			addToast(
				'Incoming Call',
				`${displayName(sender)} is calling...`,
				sender,
			);
			break;
		}

		case 'answer': {
			if (!peerConnection) return;

			// Accept answers during the initial call setup AND during
			// renegotiation (e.g. screen share added/removed while active).
			// Without this, renegotiation answers are silently dropped and
			// the peer connection gets stuck in "have-local-offer" state.
			const isInitialAnswer = currentState.state === 'ringing_out';
			const isRenegotiation = currentState.state === 'active' || currentState.state === 'connecting';
			if (!isInitialAnswer && !isRenegotiation) return;

			if (isInitialAnswer) {
				stopRingback();
			}

			const answer = JSON.parse(payloadStr) as RTCSessionDescriptionInit;
			await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));

			// Flush any ICE candidates that arrived before the answer
			// (possible when signals are batched in the same poll cycle)
			if (pendingCandidates.length > 0) {
				console.log('[voice] Flushing', pendingCandidates.length, 'buffered ICE candidates after answer');
				for (const c of pendingCandidates) {
					await peerConnection.addIceCandidate(new RTCIceCandidate(c));
				}
				pendingCandidates = [];
			}

			if (isInitialAnswer) {
				updateState({ state: 'connecting' });
				console.log('[voice] Remote answer set, ICE checking should begin');
			} else {
				console.log('[voice] Renegotiation answer applied (screen share change)');
			}
			break;
		}

		case 'ice_candidate': {
			const candidate = JSON.parse(payloadStr) as RTCIceCandidateInit;

			if (peerConnection && peerConnection.remoteDescription) {
				await peerConnection.addIceCandidate(new RTCIceCandidate(candidate));
			} else {
				// Buffer until remote description is set
				pendingCandidates.push(candidate);
			}
			break;
		}

		case 'hangup': {
			console.log('[voice] Peer hung up');
			cleanup();
			updateState({ state: 'ended', error: 'Call ended by peer' });
			// Drain stale signals immediately so nothing contaminates next call
			invoke('clear_voice_signals').catch(() => {});
			setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 2000);
			break;
		}

		case 'reject': {
			console.log('[voice] Call rejected by peer');
			cleanup();
			updateState({ state: 'ended', error: 'Call rejected' });
			invoke('clear_voice_signals').catch(() => {});
			setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 2000);
			break;
		}

		case 'peer_unavailable': {
			console.log('[voice] Peer is offline');
			cleanup();
			updateState({ state: 'ended', error: 'Peer is offline' });
			invoke('clear_voice_signals').catch(() => {});
			setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 2000);
			break;
		}

		default:
			console.warn('[voice] Unknown signal type:', signalType);
	}
}

// ── Internal helpers ────────────────────────────────────────────────

function markActive() {
	const s = get(voiceCallStore);
	if (s.state === 'connecting' || s.state === 'ringing_out') {
		console.log('[voice] Call is now active');
		updateState({ state: 'active', startTime: Date.now() });
	}
}

function markFailed(reason: string) {
	const s = get(voiceCallStore);
	if (s.state !== 'idle' && s.state !== 'ended') {
		console.log('[voice] Call failed:', reason);
		updateState({ state: 'ended', error: reason });
		cleanup();
		setTimeout(() => updateState({ state: 'idle', peerPubkey: null, error: null }), 3000);
	}
}

function setupPeerConnectionHandlers(peerPubkey: string) {
	if (!peerConnection) return;
	const pc = peerConnection; // capture ref for closures

	// ICE candidate: send to peer via signaling server
	pc.onicecandidate = (event) => {
		if (event.candidate) {
			const candidatePayload = new TextEncoder().encode(JSON.stringify(event.candidate.toJSON()));
			invoke('send_voice_signal', {
				recipient: peerPubkey,
				signalType: 'ice_candidate',
				payload: Array.from(candidatePayload),
			}).catch(e => {
				console.error('[voice] Failed to send ICE candidate:', e);
			});
		}
	};

	// Log ICE gathering progress
	pc.onicegatheringstatechange = () => {
		console.log('[voice] ICE gathering state:', pc.iceGatheringState);
	};

	// ICE connection state changes (older API, broader support)
	pc.oniceconnectionstatechange = () => {
		const state = pc.iceConnectionState;
		console.log('[voice] ICE connection state:', state);

		switch (state) {
			case 'connected':
			case 'completed':
				markActive();
				break;
			case 'disconnected':
				markFailed('Connection lost');
				break;
			case 'failed':
				markFailed('Connection failed (NAT traversal may have failed)');
				break;
		}
	};

	// Peer connection state changes (newer API, fires more reliably in
	// Chromium-based WebViews like Tauri on Windows)
	pc.onconnectionstatechange = () => {
		const state = pc.connectionState;
		console.log('[voice] Peer connection state:', state);

		switch (state) {
			case 'connected':
				markActive();
				break;
			case 'disconnected':
				markFailed('Connection lost');
				break;
			case 'failed':
				markFailed('Connection failed');
				break;
		}
	};

	// Remote tracks received (audio and/or video)
	pc.ontrack = (event) => {
		console.log('[voice] Remote track received:', event.track.kind);
		if (event.track.kind === 'audio') {
			if (!remoteAudio) {
				remoteAudio = new Audio();
				remoteAudio.autoplay = true;
			}
			remoteAudio.srcObject = event.streams[0] || new MediaStream([event.track]);
		} else if (event.track.kind === 'video') {
			// Peer started screen sharing — store the stream and update state.
			// The video element may not exist yet (it's conditionally rendered
			// based on remoteScreenSharing), so we save the stream and attach
			// it when bindRemoteVideo is called.
			console.log('[voice] Remote screen share track received');
			pendingRemoteStream = event.streams[0] || new MediaStream([event.track]);
			updateState({ remoteScreenSharing: true });
			// If the video element already exists, attach immediately
			if (remoteVideo) {
				remoteVideo.srcObject = pendingRemoteStream;
				remoteVideo.muted = true;
				remoteVideo.play().catch(() => {
					console.warn('[voice] Autoplay blocked on remote video');
				});
			}
			// When the remote screen share track ends (mute or removal), update state
			event.track.onended = () => {
				console.log('[voice] Remote screen share ended');
				updateState({ remoteScreenSharing: false });
				pendingRemoteStream = null;
				if (remoteVideo) {
					remoteVideo.srcObject = null;
				}
			};
			// Also detect track being muted (some browsers fire mute instead of ended)
			event.track.onmute = () => {
				console.log('[voice] Remote screen share track muted');
			};
			event.track.onunmute = () => {
				console.log('[voice] Remote screen share track unmuted');
			};
		}
	};
}
