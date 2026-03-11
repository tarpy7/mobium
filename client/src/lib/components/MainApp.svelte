<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/core';
	import IconRail from './IconRail.svelte';
	import ContextPanel from './ContextPanel.svelte';
	import Chat from './Chat.svelte';
	import ConnectionModal from './ConnectionModal.svelte';
	import Toast from './Toast.svelte';
	import VoiceCall from './VoiceCall.svelte';
	import { connectionStore, activeConversationStore, conversationsStore } from '$lib/stores';
	import type { Conversation } from '$lib/stores';

	let showConnectionModal = $state(false);
	let activeView = $state('home');
	let previousView = $state('home');

	interface DbConversation {
		id: string;
		name: string;
		conversation_type: string;
		created_at: number;
		last_message_at: number | null;
	}

	onMount(async () => {
		try {
			const dbConvos = await invoke<DbConversation[]>('get_conversations');
			if (dbConvos.length > 0) {
				const mapped: Conversation[] = dbConvos.map(c => ({
					id: c.id,
					name: c.name,
					type: c.conversation_type === 'dm' ? 'dm' as const : 'group' as const,
					lastMessageAt: c.last_message_at ? c.last_message_at * 1000 : undefined,
					unreadCount: 0,
				}));
				conversationsStore.set(mapped);
			}
		} catch (e) { console.error('Failed to load conversations:', e); }

		try {
			const connected = await invoke<boolean>('get_connection_status');
			connectionStore.update(s => ({ ...s, connected }));
		} catch (e) { console.error('Failed to get connection status:', e); }
	});

	function handleViewChange(view: string) {
		// Toggle: clicking the same view goes back to previous
		if (view === activeView && (view === 'settings' || view === 'friends' || view === 'create')) {
			activeView = previousView;
			return;
		}
		previousView = activeView;
		activeView = view;
		if (view.startsWith('channel:')) {
			activeConversationStore.set(view.slice(8));
		}
	}

	function handleSelect(id: string) {
		activeConversationStore.set(id);
		// If selecting a channel from friends/create/settings, switch view to that channel
		const conv = $conversationsStore.find(c => c.id === id);
		if (conv?.type === 'group' && !activeView.startsWith('channel:')) {
			previousView = activeView;
			activeView = 'channel:' + id;
		}
	}

	function handleLock() {
		import('$lib/stores').then(m => {
			m.identityStore.set({ pubkey: null, mnemonic: null });
			m.connectionStore.set({ connected: false, serverUrl: null });
			m.conversationsStore.set([]);
			m.activeConversationStore.set(null);
		});
	}
</script>

<div class="flex h-full">
	<!-- Icon Rail -->
	<IconRail {activeView} onviewchange={handleViewChange} onconnect={() => showConnectionModal = !showConnectionModal} />

	<!-- Context Panel -->
	<ContextPanel {activeView} onselect={handleSelect} onlock={handleLock} />

	<!-- Main Area -->
	<div class="flex-1 flex flex-col bg-background">
		{#if $activeConversationStore}
			<Chat />
		{:else}
			<div class="flex h-full items-center justify-center">
				<div class="text-center">
					<div class="mb-3 text-4xl opacity-15">✦</div>
					<div class="text-sm text-text-muted/70">Select a conversation</div>
					{#if !$connectionStore.connected}
						<button onclick={() => showConnectionModal = true}
							class="mt-4 rounded-xl bg-primary/15 border border-primary/20 px-5 py-2 text-xs text-primary hover:bg-primary/25 transition">
							Connect to server
						</button>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</div>

<VoiceCall />
<Toast />

{#if showConnectionModal}
	<ConnectionModal on:close={() => showConnectionModal = false} />
{/if}
