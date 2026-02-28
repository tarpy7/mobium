<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { voiceCallStore, displayName, type VoiceCall } from '$lib/stores';
	import { acceptCall, rejectCall, endCall, toggleMute, handleVoiceSignal, startScreenShare, stopScreenShare, bindRemoteVideo } from '$lib/voice';
	import { get } from 'svelte/store';

	let remoteVideoEl = $state<HTMLVideoElement | null>(null);
	let showDmScreenShare = $state(true);

	// Bind the remote video element whenever it changes.
	// The element is always in the DOM (hidden via CSS when not sharing),
	// so bindRemoteVideo can attach a pending stream immediately.
	$effect(() => {
		bindRemoteVideo(remoteVideoEl);
		return () => bindRemoteVideo(null);
	});

	// Auto-show screen share view when a new remote share starts
	$effect(() => {
		if (call.remoteScreenSharing) {
			showDmScreenShare = true;
		}
	});

	// Poll both the Rust backend for incoming voice signals AND the Svelte
	// store for state changes.  This works around Tauri 2's unreliable
	// event bus for events emitted from spawned async tasks (same root
	// cause that required a DB-polling fallback in Chat.svelte).
	let call = $state<VoiceCall>(get(voiceCallStore));
	let elapsed = $state('00:00');
	let pollingSince = 0; // timestamp when current poll started (0 = not polling)

	$effect(() => {
		const interval = setInterval(async () => {
			// Prevent overlapping async polls, but auto-reset if stuck for >5s
			// (e.g. invoke hung on a held RwLock or unresolved WebRTC op)
			const now = Date.now();
			if (pollingSince > 0) {
				if (now - pollingSince < 5000) return; // still within timeout
				console.warn('[VoiceCall] Poll guard stuck for >5s — resetting');
			}
			pollingSince = now;
			try {
				// Drain any voice signals buffered in Rust AppState
				const signals = await invoke<[string, string, number[]][]>('poll_voice_signals');
				for (const [sender, signalType, payload] of signals) {
					await handleVoiceSignal(sender, signalType, payload);
				}
			} catch {
				// Not connected / command not available — ignore
			}
			pollingSince = 0;

			// Read the (now possibly updated) store into local $state
			const current: VoiceCall = get(voiceCallStore);
			call = current;

			// Update elapsed time while active
			if (current.state === 'active' && current.startTime) {
				const secs = Math.floor((Date.now() - current.startTime) / 1000);
				const m = String(Math.floor(secs / 60)).padStart(2, '0');
				const s = String(secs % 60).padStart(2, '0');
				elapsed = `${m}:${s}`;
			} else {
				elapsed = '00:00';
			}
		}, 250);
		return () => clearInterval(interval);
	});

	function peerName(): string {
		return call.peerPubkey ? displayName(call.peerPubkey) : 'Unknown';
	}
</script>

{#if call.state !== 'idle'}
<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
	<div class="{call.remoteScreenSharing ? 'w-[80vw] max-w-4xl' : 'w-80'} rounded-2xl bg-surface p-6 shadow-2xl border border-surface-light transition-all duration-300">

		<!-- Incoming call -->
		{#if call.state === 'ringing_in'}
			<div class="text-center">
				<div class="mb-2 text-lg font-semibold text-text">Incoming Call</div>
				<div class="mb-1 text-sm text-text-muted">{peerName()}</div>
				<div class="mb-6 animate-pulse text-xs text-primary">Ringing...</div>
				<div class="flex justify-center gap-4">
					<button
						onclick={() => rejectCall()}
						class="flex h-14 w-14 items-center justify-center rounded-full bg-danger text-white shadow-lg transition hover:bg-danger/80"
						title="Decline"
					>
						<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
					</button>
					<button
						onclick={() => acceptCall()}
						class="flex h-14 w-14 items-center justify-center rounded-full bg-success text-white shadow-lg transition hover:bg-success/80"
						title="Accept"
					>
						<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
						</svg>
					</button>
				</div>
			</div>

		<!-- Outgoing call (ringing) -->
		{:else if call.state === 'ringing_out'}
			<div class="text-center">
				<div class="mb-2 text-lg font-semibold text-text">Calling</div>
				<div class="mb-1 text-sm text-text-muted">{peerName()}</div>
				<div class="mb-6 animate-pulse text-xs text-primary">Ringing...</div>
				<div class="flex justify-center">
					<button
						onclick={() => endCall()}
						class="flex h-14 w-14 items-center justify-center rounded-full bg-danger text-white shadow-lg transition hover:bg-danger/80"
						title="Cancel call"
					>
						<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 8l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2M5 3a2 2 0 00-2 2v1c0 8.284 6.716 15 15 15h1a2 2 0 002-2v-3.28a1 1 0 00-.684-.948l-4.493-1.498a1 1 0 00-1.21.502l-1.13 2.257a11.042 11.042 0 01-5.516-5.516l2.257-1.13a1 1 0 00.502-1.21L8.228 3.684A1 1 0 007.28 3H5z" />
						</svg>
					</button>
				</div>
			</div>

		<!-- Connecting -->
		{:else if call.state === 'connecting'}
			<div class="text-center">
				<div class="mb-2 text-lg font-semibold text-text">Connecting</div>
				<div class="mb-1 text-sm text-text-muted">{peerName()}</div>
				<div class="mb-6 animate-pulse text-xs text-text-muted">Establishing peer-to-peer connection...</div>
				<div class="flex justify-center">
					<button
						onclick={() => endCall()}
						class="flex h-14 w-14 items-center justify-center rounded-full bg-danger text-white shadow-lg transition hover:bg-danger/80"
						title="Cancel"
					>
						<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
						</svg>
					</button>
				</div>
			</div>

		<!-- Active call -->
		{:else if call.state === 'active'}
			<div class="text-center">
				<div class="mb-2 text-lg font-semibold text-text">In Call</div>
				<div class="mb-1 text-sm text-text-muted">{peerName()}</div>
				<div class="mb-4 font-mono text-sm text-success">{elapsed}</div>

				<!-- Remote screen share video (always in DOM, hidden when no stream) -->
				<div class="mb-4 overflow-hidden rounded-lg border border-surface-light bg-black {call.remoteScreenSharing && showDmScreenShare ? '' : 'hidden'}">
					<div class="flex items-center justify-between bg-surface-light/50 px-3 py-1">
						<div class="text-xs text-text-muted">{peerName()} is sharing their screen</div>
						<button
							onclick={() => { showDmScreenShare = false; }}
							class="text-text-muted hover:text-text transition p-0.5"
							title="Hide screen share"
						>
							<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
							</svg>
						</button>
					</div>
					<!-- svelte-ignore a11y_media_has_caption -->
					<!-- svelte-ignore non_reactive_update -->
					<video
						bind:this={remoteVideoEl}
						autoplay
						playsinline
						muted
						class="w-full max-h-[60vh] object-contain"
					></video>
				</div>
				{#if call.remoteScreenSharing && !showDmScreenShare}
					<button
						onclick={() => { showDmScreenShare = true; }}
						class="mb-3 flex items-center gap-1.5 rounded-lg bg-primary/15 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/25 transition mx-auto"
					>
						<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
						</svg>
						Show screen share
					</button>
				{/if}

				<div class="flex justify-center gap-3">
					<button
						onclick={() => toggleMute()}
						class="flex h-12 w-12 items-center justify-center rounded-full transition shadow-lg {call.muted ? 'bg-warning text-white' : 'bg-surface-light text-text hover:bg-surface-light/80'}"
						title={call.muted ? 'Unmute' : 'Mute'}
					>
						{#if call.muted}
							<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2" />
							</svg>
						{:else}
							<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z" />
							</svg>
						{/if}
					</button>
					<button
						onclick={() => call.screenSharing ? stopScreenShare() : startScreenShare()}
						class="flex h-12 w-12 items-center justify-center rounded-full transition shadow-lg {call.screenSharing ? 'bg-primary text-white' : 'bg-surface-light text-text hover:bg-surface-light/80'}"
						title={call.screenSharing ? 'Stop sharing' : 'Share screen'}
					>
						<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
						</svg>
					</button>
					<button
						onclick={() => endCall()}
						class="flex h-12 w-12 items-center justify-center rounded-full bg-danger text-white shadow-lg transition hover:bg-danger/80"
						title="Hang up"
					>
						<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 8l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2M5 3a2 2 0 00-2 2v1c0 8.284 6.716 15 15 15h1a2 2 0 002-2v-3.28a1 1 0 00-.684-.948l-4.493-1.498a1 1 0 00-1.21.502l-1.13 2.257a11.042 11.042 0 01-5.516-5.516l2.257-1.13a1 1 0 00.502-1.21L8.228 3.684A1 1 0 007.28 3H5z" />
						</svg>
					</button>
				</div>
				{#if call.screenSharing}
					<div class="mt-2 text-xs text-primary">Sharing your screen</div>
				{/if}
			</div>

		<!-- Ended (error / info) -->
		{:else if call.state === 'ended'}
			<div class="text-center">
				<div class="mb-2 text-lg font-semibold text-text">Call Ended</div>
				{#if call.error}
					<div class="text-sm text-danger">{call.error}</div>
				{/if}
			</div>
		{/if}

	</div>
</div>
{/if}
