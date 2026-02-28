<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';
	import { connectionStore, conversationsStore, activeConversationStore, upsertConversation, identityStore, sidebarFilterStore } from '$lib/stores';
	import type { SidebarFilter } from '$lib/stores';
	import UserList from './UserList.svelte';

	const dispatch = createEventDispatcher();

	let searchQuery = $state('');
	let showCreateChannel = $state(false);
	let newChannelName = $state('');
	let showJoinChannel = $state(false);
	let joinChannelId = $state('');
	let joinChannelName = $state('');
	let copiedChannelId = $state<string | null>(null);
	let showSettings = $state(false);
	let showPeople = $state(false);
	let copiedPubkey = $state(false);

	function truncatePubkey(pk: string | null): string {
		if (!pk) return 'Unknown';
		if (pk.length <= 16) return pk;
		return `${pk.substring(0, 8)}...${pk.substring(pk.length - 8)}`;
	}

	async function createChannel() {
		if (!newChannelName.trim()) return;
		try {
			const channelId = await invoke<string>('create_channel', { channelName: newChannelName.trim() });
			upsertConversation({
				id: channelId,
				name: newChannelName.trim(),
				type: 'group',
				unreadCount: 0,
			});
			activeConversationStore.set(channelId);
			newChannelName = '';
			showCreateChannel = false;
		} catch (e) {
			console.error('Failed to create channel:', e);
		}
	}

	async function joinChannel() {
		if (!joinChannelId.trim()) return;
		const name = joinChannelName.trim() || `Channel ${joinChannelId.substring(0, 8)}`;
		try {
			await invoke('join_channel', { channelId: joinChannelId.trim(), channelName: name });
			upsertConversation({
				id: joinChannelId.trim(),
				name,
				type: 'group',
				unreadCount: 0,
			});
			activeConversationStore.set(joinChannelId.trim());
			joinChannelId = '';
			joinChannelName = '';
			showJoinChannel = false;
		} catch (e) {
			console.error('Failed to join channel:', e);
		}
	}

	function formatTime(timestamp: number): string {
		const date = new Date(timestamp);
		const now = new Date();
		const diff = now.getTime() - date.getTime();
		const days = Math.floor(diff / (1000 * 60 * 60 * 24));

		if (days === 0) {
			return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		} else if (days === 1) {
			return 'Yesterday';
		} else if (days < 7) {
			return date.toLocaleDateString([], { weekday: 'short' });
		} else {
			return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
		}
	}

	function selectConversation(id: string) {
		activeConversationStore.set(id);
	}

	const filteredConversations = $derived(
		$conversationsStore
			.filter(c => {
				// Text search filter
				if (searchQuery && !c.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
				// Type filter
				if ($sidebarFilterStore === 'dms') return c.type === 'dm';
				if ($sidebarFilterStore === 'channels') return c.type === 'group';
				return true;
			})
			.sort((a, b) => (b.lastMessageAt ?? 0) - (a.lastMessageAt ?? 0))
	);

	const dmCount = $derived($conversationsStore.filter(c => c.type === 'dm').length);
	const dmUnreadCount = $derived($conversationsStore.filter(c => c.type === 'dm').reduce((sum, c) => sum + c.unreadCount, 0));
</script>

<div class="flex h-full w-80 flex-col border-r border-surface-light bg-surface">
	<!-- Header -->
	<div class="border-b border-surface-light p-4">
		<div class="mb-4 flex items-center justify-between">
			<h1 class="text-xl font-bold text-text">Mobium</h1>
			<div class="flex items-center gap-2">
				{#if $connectionStore.connected}
					<div class="h-2 w-2 rounded-full bg-success" title="Connected"></div>
				{:else}
					<div class="h-2 w-2 rounded-full bg-danger" title="Disconnected"></div>
				{/if}
			</div>
		</div>

		<!-- Search -->
		<div class="relative">
			<input
				type="text"
				bind:value={searchQuery}
				placeholder="Search conversations..."
				class="w-full rounded-lg bg-background px-4 py-2 pr-10 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
			/>
			<svg class="absolute right-3 top-2.5 h-4 w-4 text-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
			</svg>
		</div>

		<!-- Filter tabs -->
		<div class="mt-3 flex gap-1">
			<button
				onclick={() => sidebarFilterStore.set('all')}
				class="flex-1 rounded-md px-2 py-1 text-xs font-medium transition {$sidebarFilterStore === 'all' ? 'bg-primary text-white' : 'bg-background text-text-muted hover:text-text'}"
			>
				All
			</button>
			<button
				onclick={() => sidebarFilterStore.set('dms')}
				class="flex-1 rounded-md px-2 py-1 text-xs font-medium transition flex items-center justify-center gap-1 {$sidebarFilterStore === 'dms' ? 'bg-primary text-white' : 'bg-background text-text-muted hover:text-text'}"
			>
				DMs
				{#if dmUnreadCount > 0}
					<span class="rounded-full bg-danger px-1.5 py-0 text-[10px] text-white leading-4">{dmUnreadCount}</span>
				{/if}
			</button>
			<button
				onclick={() => sidebarFilterStore.set('channels')}
				class="flex-1 rounded-md px-2 py-1 text-xs font-medium transition {$sidebarFilterStore === 'channels' ? 'bg-primary text-white' : 'bg-background text-text-muted hover:text-text'}"
			>
				Channels
			</button>
		</div>
	</div>

	<!-- Conversations List -->
	<div class="flex-1 overflow-y-auto">
		{#if filteredConversations.length === 0}
			<div class="p-4 text-center text-text-muted">
				{#if searchQuery}
					No conversations found
				{:else if $sidebarFilterStore === 'dms'}
					<div class="py-8">
						<div class="mb-2 text-3xl opacity-20">💬</div>
						<div class="text-sm">No direct messages yet</div>
						<div class="mt-1 text-xs">Use the People button to start a DM</div>
					</div>
				{:else if $sidebarFilterStore === 'channels'}
					<div class="py-8">
						<div class="mb-2 text-3xl opacity-20">📢</div>
						<div class="text-sm">No channels yet</div>
						<div class="mt-1 text-xs">Create or join a channel below</div>
					</div>
				{:else}
					<div class="py-8">
						<div class="mb-2 text-4xl opacity-20">👋</div>
						<div class="text-sm">No conversations yet</div>
						{#if !$connectionStore.connected}
							<button
								onclick={() => dispatch('connect')}
								class="mt-4 text-primary hover:underline"
							>
								Connect to server
							</button>
						{/if}
					</div>
				{/if}
			</div>
		{:else}
			{#each filteredConversations as conversation}
				<div
					role="button"
					tabindex="0"
					onclick={() => selectConversation(conversation.id)}
					onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && selectConversation(conversation.id)}
					class="group w-full border-b border-surface-light p-4 text-left transition hover:bg-surface-light cursor-pointer {$activeConversationStore === conversation.id ? 'bg-surface-light' : ''}"
				>
					<div class="flex items-start justify-between">
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-full bg-primary/20 text-lg">
								{conversation.type === 'dm' ? '👤' : '👥'}
							</div>
							<div class="flex-1 min-w-0">
								<div class="flex items-center gap-2">
									<span class="font-semibold text-text truncate">{conversation.name}</span>
									{#if conversation.unreadCount > 0}
										<span class="rounded-full bg-primary px-2 py-0.5 text-xs text-white flex-shrink-0">
											{conversation.unreadCount}
										</span>
									{/if}
								</div>
								{#if conversation.lastMessage}
									<div class="mt-1 truncate text-sm text-text-muted">
										{conversation.lastMessage}
									</div>
								{/if}
							</div>
						</div>
						<div class="flex flex-col items-end gap-1 flex-shrink-0">
							{#if conversation.lastMessageAt}
								<span class="text-xs text-text-muted">
									{formatTime(conversation.lastMessageAt)}
								</span>
							{/if}
							<button
								onclick={(e: MouseEvent) => { e.stopPropagation(); navigator.clipboard.writeText(conversation.id); copiedChannelId = conversation.id; setTimeout(() => copiedChannelId = null, 1500); }}
								class="text-xs text-text-muted/50 hover:text-primary transition opacity-0 group-hover:opacity-100"
								title="Copy channel ID"
							>
								{copiedChannelId === conversation.id ? 'Copied' : 'ID'}
							</button>
						</div>
					</div>
				</div>
			{/each}
		{/if}
	</div>

	<!-- Channel Actions -->
	{#if showCreateChannel}
		<div class="border-t border-surface-light p-3">
			<div class="text-xs font-semibold text-text-muted mb-2">Create Channel</div>
			<input
				type="text"
				bind:value={newChannelName}
				placeholder="Channel name..."
				class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary mb-2"
				onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && createChannel()}
			/>
			<div class="flex gap-2">
				<button onclick={createChannel} class="flex-1 rounded-lg bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary-dark">Create</button>
				<button onclick={() => { showCreateChannel = false; }} class="flex-1 rounded-lg bg-surface-light px-3 py-1.5 text-xs text-text-muted hover:text-text">Cancel</button>
			</div>
		</div>
	{/if}

	{#if showJoinChannel}
		<div class="border-t border-surface-light p-3">
			<div class="text-xs font-semibold text-text-muted mb-2">Join Channel</div>
			<input
				type="text"
				bind:value={joinChannelId}
				placeholder="Channel ID (hex)..."
				class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary mb-2"
			/>
			<input
				type="text"
				bind:value={joinChannelName}
				placeholder="Display name (optional)..."
				class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary mb-2"
				onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && joinChannel()}
			/>
			<div class="flex gap-2">
				<button onclick={joinChannel} class="flex-1 rounded-lg bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary-dark">Join</button>
				<button onclick={() => { showJoinChannel = false; }} class="flex-1 rounded-lg bg-surface-light px-3 py-1.5 text-xs text-text-muted hover:text-text">Cancel</button>
			</div>
		</div>
	{/if}

	<!-- People Panel -->
	{#if showPeople}
		<div class="border-t border-surface-light max-h-80 overflow-hidden flex flex-col">
			<UserList onclose={() => { showPeople = false; }} />
		</div>
	{/if}

	<!-- Settings Panel (slides up from footer) -->
	{#if showSettings}
		<div class="border-t border-surface-light p-3 bg-surface-light/50">
			<div class="text-xs font-semibold text-text-muted mb-2">Your Identity</div>
			<div class="flex items-center gap-2 mb-3">
				<code class="flex-1 text-xs text-text bg-background rounded px-2 py-1 truncate" title={$identityStore.pubkey || ''}>
					{truncatePubkey($identityStore.pubkey)}
				</code>
				<button
					onclick={() => {
						if ($identityStore.pubkey) {
							navigator.clipboard.writeText($identityStore.pubkey);
							copiedPubkey = true;
							setTimeout(() => copiedPubkey = false, 1500);
						}
					}}
					class="text-xs text-text-muted hover:text-primary transition flex-shrink-0"
					title="Copy public key"
				>
					{copiedPubkey ? 'Copied!' : 'Copy'}
				</button>
			</div>
			<button
				onclick={async () => {
					try {
						await invoke('lock_profile');
						showSettings = false;
						dispatch('locked');
					} catch (e) {
						console.error('Failed to lock profile:', e);
					}
				}}
				class="w-full rounded-lg bg-danger/20 px-3 py-1.5 text-xs text-danger hover:bg-danger/30 mb-2"
			>
				🔒 Lock Profile
			</button>
			<button
				onclick={() => { showSettings = false; }}
				class="w-full rounded-lg bg-surface-light px-3 py-1.5 text-xs text-text-muted hover:text-text"
			>
				Close
			</button>
		</div>
	{/if}

	<!-- Footer -->
	<div class="border-t border-surface-light p-4">
		<div class="flex items-center justify-between">
			<button
				onclick={() => dispatch('connect')}
				class="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-text-muted transition hover:bg-surface-light hover:text-text"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
				</svg>
				{#if $connectionStore.connected}
					Connected
				{:else}
					Connect
				{/if}
			</button>

		<div class="flex items-center gap-1">
			<button
				onclick={() => { showPeople = !showPeople; showCreateChannel = false; showJoinChannel = false; showSettings = false; }}
				class="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition hover:bg-surface-light {showPeople ? 'text-primary bg-surface-light' : 'text-text-muted hover:text-text'}"
				title="People"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
				</svg>
				People
			</button>
			<button
				onclick={() => { showCreateChannel = !showCreateChannel; showJoinChannel = false; showPeople = false; showSettings = false; }}
				class="flex items-center justify-center rounded-lg p-2 text-sm text-text-muted transition hover:bg-surface-light hover:text-text"
				title="Create Channel"
				disabled={!$connectionStore.connected}
			>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
					</svg>
				</button>
			<button
				onclick={() => { showJoinChannel = !showJoinChannel; showCreateChannel = false; showPeople = false; showSettings = false; }}
				class="flex items-center justify-center rounded-lg p-2 text-sm text-text-muted transition hover:bg-surface-light hover:text-text"
				title="Join Channel"
				disabled={!$connectionStore.connected}
			>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
					</svg>
				</button>
			<button
				onclick={() => { showSettings = !showSettings; showCreateChannel = false; showJoinChannel = false; showPeople = false; }}
				class="flex items-center justify-center rounded-lg p-2 text-sm text-text-muted transition hover:bg-surface-light hover:text-text"
				title="Settings"
			>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
					</svg>
				</button>
			</div>
		</div>
	</div>
</div>