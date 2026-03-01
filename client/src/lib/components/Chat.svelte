<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { activeConversationStore, messagesStore, conversationsStore, addMessage, connectionStore, clearUnread, displayName, nicknamesStore, voiceCallStore, channelVoiceStore, addToast } from '$lib/stores';
	import type { Message } from '$lib/stores';
	import MemberList from './MemberList.svelte';
	import { startCall } from '$lib/voice';
	import { joinVoice, leaveVoice, toggleVoiceMute } from '$lib/channelVoice';
	import { startChannelScreenShare, stopChannelScreenShare, bindScreenVideo } from '$lib/channelScreen';
	import type { ScreenQuality } from '$lib/stores/index';

	let newMessage = $state('');
	let messagesContainer: HTMLDivElement;
	let loadedConversations = $state(new Set<string>());
	let copiedId = $state(false);
	let editingNickname = $state<string | null>(null);
	let nicknameInput = $state('');
	let showMembers = $state(false);
	let showScreenQualityPicker = $state(false);
	let channelScreenVideoEl = $state<HTMLVideoElement | null>(null);
	let showChannelScreenShare = $state(true);
	let dmSessionStatus = $state<'unknown' | 'establishing' | 'active'>('unknown');

	const activeConversation = $derived(
		$conversationsStore.find(c => c.id === $activeConversationStore)
	);

	let messages = $state<import('$lib/stores').Message[]>([]);
	
	// Reactively update messages when the store or active conversation changes
	$effect(() => {
		const id = $activeConversationStore;
		const store = $messagesStore;
		messages = id ? (store.get(id) || []) : [];
	});

	// Load messages from client DB when conversation changes, and clear unread
	$effect(() => {
		const convId = $activeConversationStore;
		if (convId) {
			clearUnread(convId);
			if (!loadedConversations.has(convId)) {
				loadedConversations.add(convId);
				loadMessagesFromDb(convId);
			}
		}
	});

	// Check DM session status when viewing a DM conversation
	$effect(() => {
		const conv = activeConversation;
		if (conv?.type === 'dm' && $connectionStore.connected) {
			invoke<boolean>('has_dm_session', { peerPubkey: conv.id }).then(has => {
				dmSessionStatus = has ? 'active' : 'unknown';
			}).catch(() => {
				dmSessionStatus = 'unknown';
			});
		}
	});

	// DB polling fallback: reload messages every 3s for the active conversation.
	// This ensures incoming messages appear even if Tauri events don't reach the
	// frontend listener (e.g. due to Tauri 2 event bus quirks with spawned tasks).
	$effect(() => {
		const convId = $activeConversationStore;
		if (!convId) return;
		const interval = setInterval(() => {
			invoke<Message[]>('get_messages', { conversationId: convId }).then(dbMessages => {
				for (const msg of dbMessages) {
					addMessage(convId, {
						...msg,
						conversationId: convId,
						status: (msg.status as Message['status']) || 'delivered',
					});
				}
			}).catch(() => {}); // silent — best-effort poll
		}, 3000);
		return () => clearInterval(interval);
	});

	async function loadMessagesFromDb(conversationId: string) {
		try {
			const dbMessages = await invoke<Message[]>('get_messages', { conversationId });
			if (dbMessages.length > 0) {
				for (const msg of dbMessages) {
					addMessage(conversationId, msg);
				}
			}
		} catch (e) {
			console.error('Failed to load messages from DB:', e);
		}

		// Also request history from server if connected
		if ($connectionStore.connected) {
			try {
				await invoke('fetch_channel_history', {
					channelId: conversationId,
					afterTimestamp: 0
				});
			} catch (e) {
				console.error('Failed to fetch channel history:', e);
			}
		}
	}

	function formatMessageTime(timestamp: number): string {
		return new Date(timestamp).toLocaleTimeString([], { 
			hour: '2-digit', 
			minute: '2-digit' 
		});
	}

	function formatFullDate(timestamp: number): string {
		return new Date(timestamp).toLocaleDateString([], {
			weekday: 'long',
			year: 'numeric',
			month: 'long',
			day: 'numeric'
		});
	}

	function shouldShowDate(index: number): boolean {
		if (index === 0) return true;
		const current = messages[index].timestamp;
		const previous = messages[index - 1].timestamp;
		const currentDate = new Date(current).setHours(0, 0, 0, 0);
		const previousDate = new Date(previous).setHours(0, 0, 0, 0);
		return currentDate !== previousDate;
	}

	/** Should we show a sender label above this message? */
	function shouldShowSender(index: number): boolean {
		const msg = messages[index];
		if (msg.isOutgoing) return false;
		if (index === 0) return true;
		return messages[index - 1].senderPubkey !== msg.senderPubkey || messages[index - 1].isOutgoing;
	}

	async function saveSenderNickname(pubkey: string) {
		const nick = nicknameInput.trim();
		if (!nick) {
			editingNickname = null;
			return;
		}
		try {
			await invoke('set_nickname', { pubkey, nickname: nick });
			nicknamesStore.update(m => {
				const nm = new Map(m);
				nm.set(pubkey, nick);
				return nm;
			});
		} catch (e) {
			console.error('Failed to save nickname:', e);
		}
		editingNickname = null;
		nicknameInput = '';
	}

	async function sendMessage() {
		if (!newMessage.trim() || !$activeConversationStore) return;

		const messageText = newMessage.trim();
		const conversationId = $activeConversationStore;
		const conversation = activeConversation;
		newMessage = '';

		// Optimistically add message to local store
		const tempId = `local-${Date.now()}-${Math.random().toString(36).substring(7)}`;
		const timestamp = Date.now();
		
		addMessage(conversationId, {
			id: tempId,
			conversationId,
			senderPubkey: 'self',
			content: messageText,
			timestamp,
			isOutgoing: true,
			status: 'sending',
		});

		try {
			if (conversation?.type === 'group') {
				// Send as channel message
				await invoke<string>('send_channel_message', { 
					channelId: conversationId, 
					content: messageText 
				});
			} else {
				// Send as direct message (X3DH + Double Ratchet)
				dmSessionStatus = 'establishing';
				await invoke<string>('send_message', { 
					recipient: conversationId, 
					content: messageText 
				});
				dmSessionStatus = 'active';
			}
			
			// Update status to sent
			messagesStore.update(store => {
				const msgs = store.get(conversationId);
				if (msgs) {
					const updated = msgs.map(m => m.id === tempId ? { ...m, status: 'sent' as const } : m);
					const newStore = new Map(store);
					newStore.set(conversationId, updated);
					return newStore;
				}
				return store;
			});
		} catch (e) {
			console.error('Failed to send message:', e);
			// Update status to error
			messagesStore.update(store => {
				const msgs = store.get(conversationId);
				if (msgs) {
					const updated = msgs.map(m => m.id === tempId ? { ...m, status: 'error' as const } : m);
					const newStore = new Map(store);
					newStore.set(conversationId, updated);
					return newStore;
				}
				return store;
			});
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter' && !event.shiftKey) {
			event.preventDefault();
			sendMessage();
		}
	}

	// Auto-scroll to bottom when new messages arrive
	$effect(() => {
		if (messages.length && messagesContainer) {
			messagesContainer.scrollTop = messagesContainer.scrollHeight;
		}
	});

	// Bind screen share video element when it appears/disappears
	$effect(() => {
		bindScreenVideo(channelScreenVideoEl);
	});

	// Auto-show channel screen share when a new sharer starts
	$effect(() => {
		if ($channelVoiceStore.remoteScreenSharer) {
			showChannelScreenShare = true;
		}
	});
</script>

{#if activeConversation}
<div class="flex h-full flex-col">
	<!-- Chat Header -->
	<div class="flex items-center justify-between border-b border-surface-light px-6 py-4">
		<div class="flex items-center gap-3">
			<div class="flex h-10 w-10 items-center justify-center rounded-full bg-primary/20 text-lg">
				{activeConversation.type === 'dm' ? '👤' : '👥'}
			</div>
			<div>
				<h2 class="font-semibold text-text">{activeConversation.name}</h2>
				<div class="text-xs text-text-muted">
					{#if activeConversation.type === 'dm'}
						{#if dmSessionStatus === 'active'}
							<span class="text-success">X3DH + Double Ratchet encrypted</span>
						{:else}
							End-to-end encrypted (session will be established on first message)
						{/if}
					{:else}
						End-to-end encrypted
						&middot; <button
							onclick={() => { navigator.clipboard.writeText(activeConversation?.id ?? ''); copiedId = true; setTimeout(() => copiedId = false, 1500); }}
							class="hover:text-primary transition inline"
							title="Copy channel ID"
						>{copiedId ? 'ID copied!' : 'Copy ID'}</button>
					{/if}
				</div>
			</div>
		</div>
		<div class="flex items-center gap-2">
		{#if activeConversation?.type === 'dm'}
			<button
				onclick={() => { if (activeConversation) startCall(activeConversation.id); }}
				disabled={!$connectionStore.connected || $voiceCallStore.state !== 'idle'}
				class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light text-text-muted hover:text-text disabled:opacity-40 disabled:cursor-not-allowed"
				title={$voiceCallStore.state !== 'idle' ? 'Already in a call' : 'Start voice call'}
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
				</svg>
				Call
			</button>
		{/if}
		{#if activeConversation?.type === 'group'}
			<!-- Channel Voice Chat -->
			{#if $channelVoiceStore.channelId === activeConversation.id}
				<!-- In voice: show mute toggle + leave button + participant count -->
				<button
					onclick={toggleVoiceMute}
					class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light {$channelVoiceStore.muted ? 'text-danger' : 'text-success'}"
					title={$channelVoiceStore.muted ? 'Unmute' : 'Mute'}
				>
					{#if $channelVoiceStore.muted}
						<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2" />
						</svg>
					{:else}
						<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
						</svg>
					{/if}
				</button>
				<!-- Screen share button + quality picker -->
				<div class="relative">
					{#if $channelVoiceStore.screenSharing}
						<!-- Currently sharing: click to stop -->
						<button
							onclick={() => { stopChannelScreenShare(); showScreenQualityPicker = false; }}
							class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition text-primary bg-primary/20 hover:bg-primary/30"
							title="Stop sharing screen ({$channelVoiceStore.screenQuality})"
						>
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
							</svg>
							<span class="uppercase">{$channelVoiceStore.screenQuality ?? ''}</span>
						</button>
					{:else}
						<!-- Not sharing: click to open quality picker -->
						<button
							onclick={() => { showScreenQualityPicker = !showScreenQualityPicker; }}
							class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light text-text-muted"
							title="Share screen"
						>
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
							</svg>
						</button>
						<!-- Quality picker dropdown -->
						{#if showScreenQualityPicker}
							<div class="absolute top-full left-0 z-50 mt-1 rounded-lg border border-surface-light bg-surface shadow-lg">
								{#each [
									{ q: 'low' as ScreenQuality, label: 'Low', desc: '360p 400kbps' },
									{ q: 'medium' as ScreenQuality, label: 'Medium', desc: '720p 1.2Mbps' },
									{ q: 'high' as ScreenQuality, label: 'High', desc: '1080p 2.5Mbps' },
								] as opt}
									<button
										onclick={() => { showScreenQualityPicker = false; startChannelScreenShare(opt.q); }}
										class="flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-surface-light first:rounded-t-lg last:rounded-b-lg"
									>
										<span class="font-medium text-text">{opt.label}</span>
										<span class="text-text-muted">{opt.desc}</span>
									</button>
								{/each}
							</div>
						{/if}
					{/if}
				</div>
				<span class="text-xs text-text-muted">{$channelVoiceStore.participants.length} in voice</span>
				{#if $channelVoiceStore.remoteScreenSharer}
					<span class="flex items-center gap-1 rounded-lg bg-primary/15 px-2 py-1 text-xs font-medium text-primary">
						<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
						</svg>
						{displayName($channelVoiceStore.remoteScreenSharer)} sharing
					</span>
				{/if}
				<button
					onclick={() => leaveVoice()}
					class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition bg-danger/20 text-danger hover:bg-danger/30"
					title="Leave voice"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 8l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2M5 3a2 2 0 00-2 2v1c0 8.284 6.716 15 15 15h1a2 2 0 002-2v-3.28a1 1 0 00-.684-.948l-4.493-1.498a1 1 0 00-1.21.502l-1.13 2.257a11.042 11.042 0 01-5.516-5.517l2.257-1.128a1 1 0 00.502-1.21L9.228 3.683A1 1 0 008.279 3H5z" />
					</svg>
					Leave
				</button>
			{:else}
				<button
					onclick={async () => {
						if (!activeConversation) return;
						try {
							await joinVoice(activeConversation.id);
						} catch (e) {
							const msg = e instanceof Error ? e.message : String(e);
							console.error('[Chat] joinVoice failed:', msg);
							addToast('Failed to join voice: ' + msg, 'error');
						}
					}}
					disabled={!$connectionStore.connected || $channelVoiceStore.channelId !== null}
					class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light text-text-muted hover:text-text disabled:opacity-40 disabled:cursor-not-allowed"
					title={$channelVoiceStore.channelId !== null ? 'Already in a voice channel' : 'Join voice chat'}
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
					</svg>
					Join Voice
				</button>
			{/if}

			<button
				onclick={() => { showMembers = !showMembers; }}
				class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light {showMembers ? 'bg-surface-light text-primary' : 'text-text-muted hover:text-text'}"
				title="Toggle member list"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
				</svg>
				Members
			</button>
		{/if}
			<button
				onclick={() => activeConversationStore.set(null)}
				class="text-text-muted hover:text-text"
				title="Close chat"
			>
				<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>
	</div>

	<!-- Channel screen share video (always in DOM when in voice, hidden via CSS when no one is sharing) -->
	{#if activeConversation?.type === 'group' && $channelVoiceStore.channelId === activeConversation?.id}
		<div class="relative border-b border-border bg-black {$channelVoiceStore.remoteScreenSharer && showChannelScreenShare ? '' : 'hidden'}">
			<div class="flex items-center justify-between bg-surface-light/50 px-3 py-1.5 text-xs text-text-muted">
				<div class="flex items-center gap-2">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
					</svg>
					{#if $channelVoiceStore.remoteScreenSharer}
						Screen shared by {displayName($channelVoiceStore.remoteScreenSharer)}
					{/if}
				</div>
				<button
					onclick={() => { showChannelScreenShare = false; }}
					class="text-text-muted hover:text-text transition p-0.5"
					title="Hide screen share"
				>
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</button>
			</div>
			<!-- svelte-ignore non_reactive_update -->
			<video
				bind:this={channelScreenVideoEl}
				class="max-h-[60vh] w-full object-contain"
				autoplay
				playsinline
				muted
			></video>
		</div>
		{#if $channelVoiceStore.remoteScreenSharer && !showChannelScreenShare}
			<div class="border-b border-border px-3 py-1.5">
				<button
					onclick={() => { showChannelScreenShare = true; }}
					class="flex items-center gap-1.5 rounded-lg bg-primary/15 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/25 transition"
				>
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
					</svg>
					Show screen share ({displayName($channelVoiceStore.remoteScreenSharer)})
				</button>
			</div>
		{/if}
	{/if}

	<!-- Content area: messages + optional member panel -->
	<div class="flex flex-1 overflow-hidden">

	<!-- Messages -->
	<div bind:this={messagesContainer} class="flex-1 overflow-y-auto p-4">
		{#if messages.length === 0}
			<div class="flex h-full items-center justify-center">
				<div class="text-center text-text-muted">
					<div class="mb-4 text-6xl opacity-20">🔒</div>
					<div class="text-sm">No messages yet</div>
					<div class="mt-2 text-xs">
						{#if activeConversation?.type === 'dm'}
							Send a message to establish an encrypted session via X3DH + Double Ratchet
						{:else}
							Messages are end-to-end encrypted
						{/if}
					</div>
				</div>
			</div>
		{:else}
			{#each messages as message, index}
				{#if shouldShowDate(index)}
					<div class="my-6 flex items-center justify-center">
						<span class="rounded-full bg-surface-light px-4 py-1 text-xs text-text-muted">
							{formatFullDate(message.timestamp)}
						</span>
					</div>
				{/if}

				<div class="mb-1 flex {message.isOutgoing ? 'justify-end' : 'justify-start'}">
					<div class="max-w-[70%]">
						{#if shouldShowSender(index)}
							<div class="mb-1 ml-1 flex items-center gap-1">
								{#if editingNickname === message.senderPubkey}
									<input
										type="text"
										bind:value={nicknameInput}
										onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') saveSenderNickname(message.senderPubkey); if (e.key === 'Escape') { editingNickname = null; } }}
										placeholder="Set nickname..."
										class="text-xs bg-background rounded px-2 py-0.5 text-text outline-none ring-1 ring-surface-light focus:ring-primary w-32"
									/>
									<button onclick={() => saveSenderNickname(message.senderPubkey)} class="text-xs text-primary">Save</button>
								{:else}
									<button
										onclick={() => { editingNickname = message.senderPubkey; nicknameInput = displayName(message.senderPubkey); }}
										class="text-xs font-semibold text-primary/80 hover:text-primary transition"
										title="Click to set nickname"
									>
										{displayName(message.senderPubkey)}
									</button>
								{/if}
							</div>
						{/if}
						<div class="rounded-2xl px-4 py-2 {message.isOutgoing ? 'rounded-br-md bg-primary text-white' : 'rounded-bl-md bg-surface-light text-text'}">
							<div class="text-sm whitespace-pre-wrap break-words">{message.content}</div>
							<div class="mt-1 flex items-center justify-end gap-1 text-xs {message.isOutgoing ? 'text-white/70' : 'text-text-muted'}">
								<span>{formatMessageTime(message.timestamp)}</span>
								{#if message.isOutgoing}
									{#if message.status === 'sending'}
										<span>⏳</span>
									{:else if message.status === 'sent'}
										<span>✓</span>
									{:else if message.status === 'delivered'}
										<span>✓✓</span>
									{:else if message.status === 'error'}
										<span class="text-danger">!</span>
									{/if}
								{/if}
							</div>
						</div>
					</div>
				</div>
			{/each}
		{/if}
	</div>

	<!-- Member List Panel -->
	{#if showMembers && activeConversation?.type === 'group'}
		<div class="w-64 border-l border-surface-light bg-surface flex-shrink-0 overflow-hidden">
			<MemberList channelId={activeConversation.id} onclose={() => { showMembers = false; }} />
		</div>
	{/if}

	</div>

	<!-- Input Area -->
	<div class="border-t border-surface-light p-4">
		<div class="flex items-end gap-2">
			<textarea
				bind:value={newMessage}
				onkeydown={handleKeydown}
				placeholder="Type a message..."
				rows="1"
				class="max-h-32 flex-1 resize-none rounded-xl bg-surface-light px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-transparent focus:ring-primary"
				style="min-height: 44px;"
			></textarea>
			<button
				onclick={sendMessage}
				disabled={!newMessage.trim()}
				class="flex h-11 w-11 items-center justify-center rounded-xl bg-primary text-white transition hover:bg-primary-dark disabled:opacity-50 disabled:hover:bg-primary"
				title="Send message"
			>
				<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
				</svg>
			</button>
		</div>
		<div class="mt-2 text-center text-xs text-text-muted">
			Press Enter to send, Shift+Enter for new line
		</div>
	</div>
</div>
{:else}
	<div class="flex h-full items-center justify-center">
		<div class="text-text-muted">Select a conversation</div>
	</div>
{/if}
