<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';
	import { connectionStore, conversationsStore, activeConversationStore, upsertConversation, identityStore, sidebarFilterStore, friendsStore, searchResultsStore, usernameStore, addToast } from '$lib/stores';
	import type { SidebarFilter, Friend } from '$lib/stores';
	import UserList from './UserList.svelte';
	import { nsfwFilterEnabled } from '$lib/nsfwFilter';
	import { featureStore, isDarkModeUnlocked, themeStore, toggleTheme, redeemKey, resetFeatures } from '$lib/features';

	const dispatch = createEventDispatcher();

	let searchQuery = $state('');
	let showCreateChannel = $state(false);
	let showJoinChannel = $state(false);
	let showPeople = $state(false);
	let showSettings = $state(false);
	let friendSearch = $state('');
	let friendSearchLoading = $state(false);
	let friendSearchTimer: ReturnType<typeof setTimeout> | null = null;

	// Load friends from local DB on mount
	$effect(() => {
		loadFriends();
	});

	async function loadFriends() {
		try {
			const list: [string, string | null][] = await invoke('get_friends');
			friendsStore.set(list.map(([pubkey, username]) => ({ pubkey, username })));
		} catch (e) { console.error('get_friends error:', e); }
	}

	function searchForFriends() {
		if (friendSearch.trim().length < 2) {
			searchResultsStore.set([]);
			return;
		}
		if (friendSearchTimer) clearTimeout(friendSearchTimer);
		friendSearchTimer = setTimeout(async () => {
			friendSearchLoading = true;
			try {
				await invoke('search_users', { query: friendSearch.trim() });
			} catch (e) { console.error('search_users error:', e); }
			friendSearchLoading = false;
		}, 300);
	}

	async function addFriend(pubkey: string, username: string | null) {
		try {
			await invoke('add_friend', { pubkey, username });
			await loadFriends();
		} catch (e) {
			console.error('add friend error:', e);
		}
	}

	async function removeFriend(pubkey: string) {
		try {
			await invoke('remove_friend', { pubkey });
			await loadFriends();
		} catch (e) {
			console.error('remove friend error:', e);
		}
	}
	let redeemKeyInput = $state('');
	let redeemError = $state('');

	function tryRedeem() {
		if (!redeemKeyInput.trim()) return;
		if (redeemKey(redeemKeyInput)) {
			redeemKeyInput = '';
			redeemError = '';
		} else {
			redeemError = 'Invalid key';
			setTimeout(() => redeemError = '', 3000);
		}
	}
	let showGroupDm = $state(false);
	let copiedPubkey = $state(false);

	// Channel forms
	let channelName = $state('');
	let joinChannelId = $state('');
	let joinChannelName = $state('');
	let joinChannelPassword = $state('');

	// Group DM
	let groupDmName = $state('');
	let groupDmMembers = $state<string[]>([]);
	let groupDmInput = $state('');

	let creatingChannel = $state(false);
	async function createChannel() {
		const name = channelName.trim();
		if (!name) { addToast('Enter a channel name', 'error'); return; }
		if (creatingChannel) return;
		creatingChannel = true;
		try {
			console.log('[createChannel] invoking with name:', name);
			const channelId = await invoke<string>('create_channel', { channelName: name });
			console.log('[createChannel] success, id:', channelId);
			upsertConversation({ id: channelId, name, type: 'group', unreadCount: 0 });
			activeConversationStore.set(channelId);
			channelName = '';
			showCreateChannel = false;
			addToast(`Channel "${name}" created`, 'success');
		} catch (e) {
			console.error('[createChannel] error:', e);
			addToast(`Failed to create channel: ${e}`, 'error');
		}
		creatingChannel = false;
	}

	async function joinChannel() {
		if (!joinChannelId.trim()) return;
		try {
			const pw = joinChannelPassword.trim() || undefined;
			await invoke('join_channel_with_password', {
				channelId: joinChannelId.trim(),
				password: pw || null,
				inviteToken: null,
			});
			const name = joinChannelName.trim() || joinChannelId.trim().substring(0, 12);
			upsertConversation({ id: joinChannelId.trim(), name, type: 'group', unreadCount: 0 });
			activeConversationStore.set(joinChannelId.trim());
			joinChannelId = '';
			joinChannelName = '';
			joinChannelPassword = '';
			showJoinChannel = false;
		} catch (e) {
			console.error('Failed to join channel:', e);
			addToast(`Failed to join channel: ${e}`, 'error');
		}
	}

	function createGroupDm() {
		if (!groupDmName.trim() || groupDmMembers.length < 2) return;
		// Create a local group DM conversation
		// Group ID = hash of sorted member pubkeys
		const sorted = [...groupDmMembers].sort().join(':');
		const groupId = `gdm_${sorted.substring(0, 32)}`;
		upsertConversation({
			id: groupId,
			name: groupDmName.trim(),
			type: 'group_dm',
			unreadCount: 0,
		});
		activeConversationStore.set(groupId);
		groupDmName = '';
		groupDmMembers = [];
		showGroupDm = false;
	}

	function addGroupDmMember() {
		const pk = groupDmInput.trim();
		if (pk && !groupDmMembers.includes(pk)) {
			groupDmMembers = [...groupDmMembers, pk];
		}
		groupDmInput = '';
	}

	function removeGroupDmMember(pk: string) {
		groupDmMembers = groupDmMembers.filter(m => m !== pk);
	}

	function truncatePubkey(pk: string | null): string {
		if (!pk) return '';
		if (pk.length <= 12) return pk;
		return `${pk.substring(0, 6)}…${pk.substring(pk.length - 6)}`;
	}

	function formatTime(timestamp: number): string {
		const date = new Date(timestamp);
		const now = new Date();
		const days = Math.floor((now.getTime() - date.getTime()) / (86400000));
		if (days === 0) return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		if (days === 1) return 'Yesterday';
		if (days < 7) return date.toLocaleDateString([], { weekday: 'short' });
		return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
	}

	function selectConversation(id: string) {
		activeConversationStore.set(id);
		clearUnread(id);
	}

	function clearUnread(id: string) {
		conversationsStore.update(convos =>
			convos.map(c => c.id === id ? { ...c, unreadCount: 0 } : c)
		);
	}

	function closeAllPanels() {
		showCreateChannel = false;
		showJoinChannel = false;
		showPeople = false;
		showSettings = false;
		showGroupDm = false;
	}

	// Derived
	const filteredConversations = $derived(
		$conversationsStore
			.filter(c => {
				if ($sidebarFilterStore === 'dms') return c.type === 'dm' || c.type === 'group_dm';
				if ($sidebarFilterStore === 'channels') return c.type === 'group';
				return true;
			})
			.filter(c => {
				if (!searchQuery) return true;
				return c.name.toLowerCase().includes(searchQuery.toLowerCase());
			})
			.sort((a, b) => (b.lastMessageAt || 0) - (a.lastMessageAt || 0))
	);

	const totalUnread = $derived($conversationsStore.reduce((s, c) => s + c.unreadCount, 0));
</script>

<div class="flex h-full w-72 flex-col border-r border-surface-light/30 bg-surface">

	<!-- Header -->
	<div class="flex items-center justify-between px-4 py-3 border-b border-surface-light/20">
		<div class="flex items-center gap-2">
			<span class="text-lg font-bold text-primary">Bonchi</span>
			<span class="flex h-2 w-2 rounded-full {$connectionStore.connected ? 'bg-accent' : 'bg-danger'}"></span>
		</div>
		<button
			onclick={() => dispatch('connect')}
			class="rounded-lg p-1.5 text-text-muted hover:text-primary hover:bg-surface-light/50 transition"
			title={$connectionStore.connected ? 'Connected' : 'Connect to server'}
		>
			<!-- Server/connection icon -->
			<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
			</svg>
		</button>
	</div>

	<!-- Filter tabs -->
	<div class="flex px-3 py-2 gap-1 border-b border-surface-light/10">
		{#each [['all', 'All'], ['dms', 'DMs'], ['channels', 'Channels']] as [key, label]}
			<button
				onclick={() => sidebarFilterStore.set(key as SidebarFilter)}
				class="flex-1 rounded-lg px-2 py-1 text-xs font-medium transition {$sidebarFilterStore === key ? 'bg-primary/20 text-primary' : 'text-text-muted hover:text-text hover:bg-surface-light/30'}"
			>
				{label}
			</button>
		{/each}
	</div>

	<!-- Search -->
	<div class="px-3 py-2">
		<input
			type="text"
			bind:value={searchQuery}
			placeholder="Search…"
			class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50"
		/>
	</div>

	<!-- Conversations -->
	<div class="flex-1 overflow-y-auto">
		{#if filteredConversations.length === 0}
			<div class="p-6 text-center text-xs text-text-muted/60">
				No conversations yet
			</div>
		{/if}

		{#each filteredConversations as conversation}
			<button
				onclick={() => selectConversation(conversation.id)}
				class="group w-full px-3 py-2.5 text-left transition hover:bg-surface-light/30 {$activeConversationStore === conversation.id ? 'bg-surface-light/40' : ''}"
			>
				<div class="flex items-center gap-2.5">
					<!-- Icon -->
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-sm flex-shrink-0 {conversation.type === 'dm' ? 'bg-primary/15 text-primary/80' : conversation.type === 'group_dm' ? 'bg-secondary/20 text-secondary' : 'bg-accent/15 text-accent/80'}">
						{#if conversation.type === 'dm'}
							<!-- User icon -->
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
							</svg>
						{:else if conversation.type === 'group_dm'}
							<!-- Group DM icon -->
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
							</svg>
						{:else}
							<!-- Channel icon -->
							<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
							</svg>
						{/if}
					</div>

					<!-- Name + preview -->
					<div class="min-w-0 flex-1">
						<div class="flex items-center justify-between">
							<span class="text-sm font-medium text-text truncate">{conversation.name}</span>
							{#if conversation.lastMessageAt}
								<span class="text-xs text-text-muted/50 flex-shrink-0 ml-2">{formatTime(conversation.lastMessageAt)}</span>
							{/if}
						</div>
						{#if conversation.lastMessage}
							<div class="text-xs text-text-muted/60 truncate">{conversation.lastMessage}</div>
						{/if}
					</div>

					<!-- Unread badge -->
					{#if conversation.unreadCount > 0}
						<span class="flex h-5 min-w-5 items-center justify-center rounded-full bg-primary px-1.5 text-xs font-bold text-white flex-shrink-0">
							{conversation.unreadCount}
						</span>
					{/if}
				</div>
			</button>
		{/each}
	</div>

	<!-- Friends Panel -->
	{#if showPeople}
		<div class="absolute inset-0 z-20 w-72 bg-surface border-r border-surface-light/30 flex flex-col">
			<div class="flex items-center justify-between border-b border-surface-light/20 px-3 py-2">
				<span class="text-xs font-semibold text-text">Friends</span>
				<button onclick={() => showPeople = false} class="text-text-muted hover:text-text p-0.5">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
				</button>
			</div>

			<!-- Search for users -->
			<div class="px-3 py-2 border-b border-surface-light/20">
				<input
					type="text"
					placeholder="Search by username…"
					bind:value={friendSearch}
					oninput={searchForFriends}
					class="w-full rounded-lg bg-background/50 border border-surface-light/30 px-2.5 py-1.5 text-xs text-text placeholder:text-text-muted/40 focus:outline-none focus:border-primary/40"
				/>
			</div>

			<div class="flex-1 overflow-y-auto">
				<!-- Search results (from server username directory) -->
				{#if friendSearch.trim().length >= 2}
					<div class="px-3 py-2">
						<div class="text-xs text-text-muted/60 mb-1.5">Search results</div>
						{#if friendSearchLoading}
							<div class="text-xs text-text-muted py-2 text-center">Searching…</div>
						{:else if $searchResultsStore.length === 0}
							<div class="text-xs text-text-muted py-2 text-center">No users found</div>
						{:else}
							{#each $searchResultsStore as user}
								<div class="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-surface-light/30 transition">
									<div>
										<div class="text-xs font-medium text-text">{user.username}</div>
										<div class="text-xs text-text-muted/50 font-mono">{user.pubkey.slice(0, 12)}…</div>
									</div>
									{#if user.pubkey === $identityStore.pubkey}
										<span class="text-xs text-text-muted/40">You</span>
									{:else if $friendsStore.some(f => f.pubkey === user.pubkey)}
										<span class="text-xs text-accent">Added ✓</span>
									{:else}
										<button
											onclick={() => addFriend(user.pubkey, user.username)}
											class="rounded-lg bg-primary/15 px-2 py-0.5 text-xs text-primary hover:bg-primary/25 transition"
										>Add</button>
									{/if}
								</div>
							{/each}
						{/if}
					</div>
				{/if}

				<!-- Your friends (stored locally) -->
				<div class="px-3 py-2 {friendSearch.trim().length >= 2 ? 'border-t border-surface-light/20' : ''}">
					<div class="text-xs text-text-muted/60 mb-1.5">Your Friends</div>
					{#if $friendsStore.length === 0}
						<div class="text-xs text-text-muted py-3 text-center">No friends yet. Search by username above to add people.</div>
					{:else}
						{#each $friendsStore as friend}
							<div class="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-light/30 transition">
								<button
									onclick={() => {
										dispatch('select', friend.pubkey);
										showPeople = false;
									}}
									class="flex items-center gap-2 flex-1 min-w-0 text-left"
								>
									<div class="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center text-xs text-primary font-bold">
										{(friend.username || friend.pubkey)[0]?.toUpperCase()}
									</div>
									<div class="flex-1 min-w-0">
										<div class="text-xs font-medium text-text truncate">{friend.username || friend.pubkey.slice(0, 12) + '…'}</div>
										<div class="text-xs text-text-muted/50 font-mono">{friend.pubkey.slice(0, 12)}…</div>
									</div>
								</button>
								<button
									onclick={() => removeFriend(friend.pubkey)}
									class="text-text-muted/30 hover:text-danger transition p-0.5"
									title="Remove"
								>
									<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
								</button>
							</div>
						{/each}
					{/if}
				</div>
			</div>
		</div>
	{/if}

	<!-- Create Channel Panel -->
	{#if showCreateChannel}
		<div class="border-t border-surface-light/20 p-3 bg-surface-light/20">
			<div class="flex items-center justify-between mb-2">
				<span class="text-xs font-semibold text-text">New Channel</span>
				<button onclick={() => showCreateChannel = false} class="text-text-muted hover:text-text p-0.5">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
				</button>
			</div>
			<input type="text" bind:value={channelName} placeholder="Channel name" onkeydown={(e) => e.key === 'Enter' && createChannel()}
				class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-2" />
			<button onclick={createChannel} disabled={creatingChannel} class="w-full rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-dark transition disabled:opacity-50">{creatingChannel ? 'Creating…' : 'Create'}</button>
		</div>
	{/if}

	<!-- Join Channel Panel -->
	{#if showJoinChannel}
		<div class="border-t border-surface-light/20 p-3 bg-surface-light/20">
			<div class="flex items-center justify-between mb-2">
				<span class="text-xs font-semibold text-text">Join Channel</span>
				<button onclick={() => showJoinChannel = false} class="text-text-muted hover:text-text p-0.5">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
				</button>
			</div>
			<input type="text" bind:value={joinChannelId} placeholder="Channel ID" class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-1.5" />
			<input type="text" bind:value={joinChannelName} placeholder="Display name (optional)" class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-1.5" />
			<input type="password" bind:value={joinChannelPassword} placeholder="Password (if required)" class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-2" />
			<button onclick={joinChannel} class="w-full rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-dark transition">Join</button>
		</div>
	{/if}

	<!-- Group DM Panel -->
	{#if showGroupDm}
		<div class="border-t border-surface-light/20 p-3 bg-surface-light/20">
			<div class="flex items-center justify-between mb-2">
				<span class="text-xs font-semibold text-text">New Group Chat</span>
				<button onclick={() => showGroupDm = false} class="text-text-muted hover:text-text p-0.5">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
				</button>
			</div>
			<input type="text" bind:value={groupDmName} placeholder="Group name"
				class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-1.5" />
			<div class="flex gap-1 mb-1.5">
				<input type="text" bind:value={groupDmInput} placeholder="Add member pubkey"
					onkeydown={(e) => e.key === 'Enter' && addGroupDmMember()}
					class="flex-1 rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50" />
				<button onclick={addGroupDmMember} class="rounded-lg bg-accent/20 px-2 text-xs text-accent hover:bg-accent/30 transition">+</button>
			</div>
			{#if groupDmMembers.length > 0}
				<div class="mb-2 flex flex-wrap gap-1">
					{#each groupDmMembers as member}
						<span class="flex items-center gap-1 rounded-full bg-secondary/15 px-2 py-0.5 text-xs text-secondary">
							{truncatePubkey(member)}
							<button onclick={() => removeGroupDmMember(member)} class="hover:text-danger">×</button>
						</span>
					{/each}
				</div>
			{/if}
			<button onclick={createGroupDm} disabled={groupDmMembers.length < 2 || !groupDmName.trim()}
				class="w-full rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary-dark transition disabled:opacity-40">
				Create Group ({groupDmMembers.length} members)
			</button>
		</div>
	{/if}

	<!-- Settings Panel -->
	{#if showSettings}
		<div class="border-t border-surface-light/20 p-3 bg-surface-light/20">
			<div class="flex items-center justify-between mb-2">
				<span class="text-xs font-semibold text-text">Settings</span>
				<button onclick={() => showSettings = false} class="text-text-muted hover:text-text p-0.5">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
				</button>
			</div>

			<!-- Pubkey -->
			<div class="flex items-center gap-1.5 mb-3">
				<code class="flex-1 text-xs text-text bg-background/50 rounded px-2 py-1 truncate" title={$identityStore.pubkey || ''}>
					{truncatePubkey($identityStore.pubkey)}
				</code>
				<button onclick={() => {
					if ($identityStore.pubkey) {
						navigator.clipboard.writeText($identityStore.pubkey);
						copiedPubkey = true;
						setTimeout(() => copiedPubkey = false, 1500);
					}
				}} class="text-xs text-text-muted hover:text-primary transition">
					{copiedPubkey ? '✓' : 'Copy'}
				</button>
			</div>

			<!-- Content Filter -->
			<div class="flex items-center justify-between mb-3">
				<div>
					<div class="text-xs font-medium text-text">Content Filter</div>
					<div class="text-xs text-text-muted/60">Block explicit media</div>
				</div>
				<button onclick={() => { nsfwFilterEnabled.update(v => !v); }}
					class="relative w-9 h-5 rounded-full transition {$nsfwFilterEnabled ? 'bg-accent' : 'bg-surface-light'}">
					<span class="absolute top-0.5 {$nsfwFilterEnabled ? 'left-4' : 'left-0.5'} w-4 h-4 rounded-full bg-white shadow transition-all"></span>
				</button>
			</div>

			<!-- Dark Mode Toggle -->
			<div class="flex items-center justify-between mb-3">
				<div>
					<div class="text-xs font-medium text-text">Dark Mode</div>
					{#if !$isDarkModeUnlocked}
						<div class="text-xs text-text-muted/60">🔒 Supporter perk</div>
					{:else}
						<div class="text-xs text-text-muted/60">Deep plum theme</div>
					{/if}
				</div>
				{#if $isDarkModeUnlocked}
					<button onclick={toggleTheme}
						class="relative w-9 h-5 rounded-full transition {$themeStore === 'dark' ? 'bg-primary' : 'bg-surface-light'}">
						<span class="absolute top-0.5 {$themeStore === 'dark' ? 'left-4' : 'left-0.5'} w-4 h-4 rounded-full bg-white shadow transition-all"></span>
					</button>
				{:else}
					<svg class="h-4 w-4 text-text-muted/40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
					</svg>
				{/if}
			</div>

			<!-- Supporter Unlock -->
			<div class="mb-3">
				{#if $featureStore.tier === 'supporter'}
					<div class="flex items-center justify-between rounded-lg bg-accent/10 border border-accent/20 px-3 py-1.5">
						<span class="text-xs text-accent font-medium">✨ Supporter unlocked</span>
						<button onclick={resetFeatures} class="text-xs text-text-muted/50 hover:text-danger transition">Reset</button>
					</div>
				{:else}
					<div class="space-y-1.5">
						<div class="text-xs font-medium text-text">Redeem Key</div>
						<div class="flex gap-1.5">
							<input
								type="password"
								placeholder="Enter unlock key"
								bind:value={redeemKeyInput}
								onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') tryRedeem(); }}
								class="flex-1 rounded-lg bg-background/50 border border-surface-light/30 px-2 py-1 text-xs text-text placeholder:text-text-muted/40 focus:outline-none focus:border-primary/40"
							/>
							<button onclick={tryRedeem}
								class="rounded-lg bg-primary/15 border border-primary/20 px-2.5 py-1 text-xs text-primary hover:bg-primary/25 transition">
								Unlock
							</button>
						</div>
						{#if redeemError}
							<div class="text-xs text-danger">{redeemError}</div>
						{/if}
					</div>
				{/if}
			</div>

			<!-- Lock -->
			<button onclick={async () => {
				try { await invoke('lock_profile'); showSettings = false; dispatch('locked'); }
				catch (e) { console.error('Failed to lock:', e); }
			}} class="w-full rounded-lg bg-danger/15 border border-danger/20 px-3 py-1.5 text-xs text-danger hover:bg-danger/25 transition flex items-center justify-center gap-1.5">
				<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
				</svg>
				Lock Profile
			</button>
		</div>
	{/if}

	<!-- Action bar -->
	<div class="flex items-center justify-around border-t border-surface-light/20 px-2 py-2">
		<button onclick={() => { closeAllPanels(); showPeople = !showPeople; }}
			class="flex flex-col items-center gap-0.5 rounded-lg px-2 py-1 transition {showPeople ? 'text-primary' : 'text-text-muted hover:text-text'}"
			title="People">
			<!-- People icon -->
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
			</svg>
			<span class="text-[10px]">People</span>
		</button>

		<button onclick={() => { closeAllPanels(); showGroupDm = !showGroupDm; }}
			class="flex flex-col items-center gap-0.5 rounded-lg px-2 py-1 transition {showGroupDm ? 'text-primary' : 'text-text-muted hover:text-text'}"
			title="New Group Chat">
			<!-- Group chat icon -->
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
			</svg>
			<span class="text-[10px]">Group</span>
		</button>

		<button onclick={() => { closeAllPanels(); showCreateChannel = !showCreateChannel; }}
			class="flex flex-col items-center gap-0.5 rounded-lg px-2 py-1 transition {showCreateChannel ? 'text-primary' : 'text-text-muted hover:text-text'}"
			title="New Channel">
			<!-- Hash/channel icon -->
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v16m8-8H4" />
			</svg>
			<span class="text-[10px]">Channel</span>
		</button>

		<button onclick={() => { closeAllPanels(); showJoinChannel = !showJoinChannel; }}
			class="flex flex-col items-center gap-0.5 rounded-lg px-2 py-1 transition {showJoinChannel ? 'text-primary' : 'text-text-muted hover:text-text'}"
			title="Join Channel">
			<!-- Login/join icon -->
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1" />
			</svg>
			<span class="text-[10px]">Join</span>
		</button>

		<button onclick={() => { closeAllPanels(); showSettings = !showSettings; }}
			class="flex flex-col items-center gap-0.5 rounded-lg px-2 py-1 transition {showSettings ? 'text-primary' : 'text-text-muted hover:text-text'}"
			title="Settings">
			<!-- Gear icon -->
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
			</svg>
			<span class="text-[10px]">Settings</span>
		</button>
	</div>
</div>
