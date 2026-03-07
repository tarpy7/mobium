<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/core';
	import Sidebar from './Sidebar.svelte';
	import Chat from './Chat.svelte';
	import ConnectionModal from './ConnectionModal.svelte';
	import Toast from './Toast.svelte';
	import VoiceCall from './VoiceCall.svelte';
	import { connectionStore, activeConversationStore, conversationsStore, sidebarFilterStore } from '$lib/stores';
	import type { Conversation } from '$lib/stores';

	let showConnectionModal = $state(false);

	/** Shape returned by the get_conversations Tauri command */
	interface DbConversation {
		id: string;
		name: string;
		conversation_type: string;
		created_at: number;
		last_message_at: number | null;
	}

	onMount(async () => {
		// Load persisted conversations from client DB
		try {
			const dbConvos = await invoke<DbConversation[]>('get_conversations');
			if (dbConvos.length > 0) {
			const mapped: Conversation[] = dbConvos.map(c => ({
				id: c.id,
				name: c.name,
				type: c.conversation_type === 'dm' ? 'dm' as const : 'group' as const,
				// DB stores seconds; frontend uses milliseconds
				lastMessageAt: c.last_message_at ? c.last_message_at * 1000 : undefined,
				unreadCount: 0,
			}));
				conversationsStore.set(mapped);
			}
		} catch (e) {
			console.error('Failed to load conversations:', e);
		}

		// Check connection status
		try {
			const connected = await invoke<boolean>('get_connection_status');
			connectionStore.update(s => ({ ...s, connected }));
		} catch (e) {
			console.error('Failed to get connection status:', e);
		}
	});

	function toggleConnectionModal() {
		showConnectionModal = !showConnectionModal;
	}
</script>

<div class="flex h-full">
	<!-- Sidebar -->
	<Sidebar on:connect={toggleConnectionModal} on:locked={() => {
		// Navigate back to login screen by resetting identity store
		import('$lib/stores').then(m => {
			m.identityStore.set({ pubkey: null, mnemonic: null });
			m.connectionStore.set({ connected: false, serverUrl: null });
			m.conversationsStore.set([]);
			m.activeConversationStore.set(null);
		});
	}} />

	<!-- Main Chat Area -->
	<div class="flex-1 flex flex-col bg-background">
		{#if $activeConversationStore}
			<Chat />
		{:else}
			<div class="flex h-full items-center justify-center">
				<div class="text-center">
					<div class="mb-3 text-4xl opacity-15">✦</div>
					<div class="text-sm text-text-muted/70">Select a conversation</div>
					{#if !$connectionStore.connected}
						<button
							onclick={toggleConnectionModal}
							class="mt-4 rounded-xl bg-primary/15 border border-primary/20 px-5 py-2 text-xs text-primary hover:bg-primary/25 transition"
						>
							Connect to server
						</button>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</div>

<!-- Voice call overlay -->
<VoiceCall />

<!-- Toast notifications -->
<Toast />

{#if showConnectionModal}
	<ConnectionModal on:close={toggleConnectionModal} />
{/if}