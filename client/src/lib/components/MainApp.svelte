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
	<Sidebar on:connect={toggleConnectionModal} />

	<!-- Main Chat Area -->
	<div class="flex-1 flex flex-col bg-background">
		{#if $activeConversationStore}
			<Chat />
		{:else}
			<div class="flex h-full items-center justify-center">
				<div class="text-center text-text-muted">
					<div class="mb-4 text-6xl opacity-20">💬</div>
					<div class="text-lg">Select a conversation to start messaging</div>
					<div class="mt-4 flex items-center justify-center gap-3">
						<button
							onclick={() => sidebarFilterStore.set('dms')}
							class="flex items-center gap-1.5 rounded-lg bg-surface px-4 py-2 text-sm text-text-muted hover:text-text hover:bg-surface-light transition border border-surface-light"
						>
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
							</svg>
							Direct Messages
						</button>
						<button
							onclick={toggleConnectionModal}
							class="flex items-center gap-1.5 rounded-lg bg-surface px-4 py-2 text-sm text-text-muted hover:text-text hover:bg-surface-light transition border border-surface-light"
						>
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
							</svg>
							Connect to Server
						</button>
					</div>
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