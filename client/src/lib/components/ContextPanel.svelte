<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import {
		conversationsStore, activeConversationStore, connectionStore,
		identityStore, friendsStore, searchResultsStore, usernameStore,
		sidebarFilterStore, upsertConversation, addToast, subChannelsStore,
		activeSubChannelStore, channelVoiceStore, displayName,
	} from '$lib/stores';
	import type { SubChannel, Conversation, Friend } from '$lib/stores';
	import { joinVoice, leaveVoice } from '$lib/channelVoice';
	import { featureStore, themeStore, redeemKey, resetFeatures, isDarkModeUnlocked } from '$lib/features';

	let {
		activeView,
		onselect,
		onlock,
	}: {
		activeView: string;
		onselect: (id: string) => void;
		onlock: () => void;
	} = $props();

	// ── Conversation list ──
	let searchQuery = $state('');

	let filteredConvos = $derived(() => {
		let convos = $conversationsStore;
		if (activeView === 'home') {
			convos = convos.filter(c => c.type === 'dm' || c.type === 'group_dm');
		} else if (activeView.startsWith('channel:')) {
			return []; // Channel view shows sub-channels, not conversation list
		}
		if (searchQuery) {
			convos = convos.filter(c => c.name.toLowerCase().includes(searchQuery.toLowerCase()));
		}
		return convos.sort((a, b) => (b.lastMessageAt || 0) - (a.lastMessageAt || 0));
	});

	// ── Friends ──
	let friendSearch = $state('');
	let friendSearchLoading = $state(false);
	let friendSearchTimer: ReturnType<typeof setTimeout> | null = null;

	async function loadFriends() {
		try {
			const list: [string, string | null][] = await invoke('get_friends');
			friendsStore.set(list.map(([pubkey, username]) => ({ pubkey, username })));
		} catch (_) {}
	}

	function searchForFriends() {
		if (friendSearch.trim().length < 2) { searchResultsStore.set([]); return; }
		if (friendSearchTimer) clearTimeout(friendSearchTimer);
		friendSearchTimer = setTimeout(async () => {
			friendSearchLoading = true;
			try { await invoke('search_users', { query: friendSearch.trim() }); } catch (_) {}
			friendSearchLoading = false;
		}, 300);
	}

	async function addFriend(pubkey: string, username: string | null) {
		try {
			await invoke('add_friend', { pubkey, username });
			await loadFriends();
			addToast('Added to friends', 'success');
		} catch (_) { addToast('Failed to add friend', 'error'); }
	}

	async function removeFriend(pubkey: string) {
		try { await invoke('remove_friend', { pubkey }); await loadFriends(); } catch (_) {}
	}

	$effect(() => { if (activeView === 'friends') loadFriends(); });

	// ── Create / Join ──
	let channelName = $state('');
	let joinId = $state('');
	let joinName = $state('');
	let joinPassword = $state('');
	let creating = $state(false);

	async function createChannel() {
		const name = channelName.trim();
		if (!name || creating) return;
		creating = true;
		try {
			const id = await invoke<string>('create_channel', { channelName: name });
			upsertConversation({ id, name, type: 'group', unreadCount: 0 });
			activeConversationStore.set(id);
			channelName = '';
			addToast(`Channel "${name}" created`, 'success');
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
		creating = false;
	}

	async function joinChannel() {
		if (!joinId.trim()) return;
		try {
			await invoke('join_channel_with_password', {
				channelId: joinId.trim(), password: joinPassword.trim() || null, inviteToken: null,
			});
			const name = joinName.trim() || joinId.trim().substring(0, 12);
			upsertConversation({ id: joinId.trim(), name, type: 'group', unreadCount: 0 });
			activeConversationStore.set(joinId.trim());
			joinId = ''; joinName = ''; joinPassword = '';
			addToast('Joined channel', 'success');
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
	}

	// ── Channel sub-channels ──
	let activeChannelId = $derived(activeView.startsWith('channel:') ? activeView.slice(8) : null);
	let activeChannel = $derived(activeChannelId ? $conversationsStore.find(c => c.id === activeChannelId) : null);
	let subChannels = $derived(activeChannelId ? ($subChannelsStore.get(activeChannelId) || []) : []);
	let collapsedCats = $state<Set<string>>(new Set());

	let grouped = $derived.by(() => {
		const map = new Map<string, SubChannel[]>();
		map.set('', []);
		for (const sub of subChannels) {
			const cat = sub.category || '';
			if (!map.has(cat)) map.set(cat, []);
			map.get(cat)!.push(sub);
		}
		return map;
	});

	let categories = $derived([...grouped.keys()].sort((a, b) => {
		if (a === '') return -1; if (b === '') return 1; return a.localeCompare(b);
	}));

	$effect(() => {
		if (activeChannelId) {
			invoke('get_sub_channels', { channelId: activeChannelId }).catch(() => {});
		}
	});

	// ── Settings ──
	let redeemInput = $state('');
	let redeemError = $state('');
	let newUsername = $state('');
	let settingUsername = $state(false);
	let usernameError = $state('');

	async function setUsername() {
		const name = newUsername.trim();
		if (!name || settingUsername) return;
		settingUsername = true;
		usernameError = '';
		try {
			await invoke('set_username', { username: name });
			usernameStore.set(name);
			newUsername = '';
			addToast('Username set!', 'success');
		} catch (e) {
			usernameError = String(e).replace('Error: ', '');
		}
		settingUsername = false;
	}

	async function tryRedeem() {
		const result = redeemKey(redeemInput.trim());
		if (result) { redeemInput = ''; redeemError = ''; addToast('Features unlocked!', 'success'); }
		else { redeemError = 'Invalid key'; }
	}

	// ── Helpers ──
	function formatTime(ts: number): string {
		const d = new Date(ts);
		const now = new Date();
		if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
	}

	function selectConversation(id: string) {
		activeConversationStore.set(id);
		onselect(id);
	}
</script>

<div class="flex h-full w-60 flex-col bg-surface/80 border-r border-surface-light/20 overflow-hidden">

	<!-- ═══════════ HOME (DMs) ═══════════ -->
	{#if activeView === 'home'}
		<div class="px-3 py-3 border-b border-surface-light/20">
			<h2 class="text-sm font-bold text-text">Messages</h2>
		</div>
		<div class="px-3 py-2">
			<input type="text" bind:value={searchQuery} placeholder="Search…"
				class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50" />
		</div>
		<div class="flex-1 overflow-y-auto">
			{#each filteredConvos() as conversation}
				<button onclick={() => selectConversation(conversation.id)}
					class="group w-full px-3 py-2 text-left transition hover:bg-surface-light/30 {$activeConversationStore === conversation.id ? 'bg-surface-light/40' : ''}">
					<div class="flex items-center gap-2.5">
						<div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/15 text-primary/80 text-sm flex-shrink-0">
							{conversation.name.charAt(0).toUpperCase()}
						</div>
						<div class="min-w-0 flex-1">
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium text-text truncate">{conversation.name}</span>
								{#if conversation.lastMessageAt}
									<span class="text-[10px] text-text-muted/50 flex-shrink-0 ml-2">{formatTime(conversation.lastMessageAt)}</span>
								{/if}
							</div>
						</div>
						{#if conversation.unreadCount > 0}
							<span class="flex h-4 min-w-4 items-center justify-center rounded-full bg-primary text-[10px] font-bold text-white px-1 flex-shrink-0">{conversation.unreadCount}</span>
						{/if}
					</div>
				</button>
			{/each}
			{#if filteredConvos().length === 0}
				<div class="p-6 text-center text-xs text-text-muted/60">No conversations yet</div>
			{/if}
		</div>

	<!-- ═══════════ FRIENDS ═══════════ -->
	{:else if activeView === 'friends'}
		<div class="px-3 py-3 border-b border-surface-light/20">
			<h2 class="text-sm font-bold text-text">Friends</h2>
		</div>
		<div class="px-3 py-2 border-b border-surface-light/20">
			<input type="text" placeholder="Search by username…" bind:value={friendSearch} oninput={searchForFriends}
				class="w-full rounded-lg bg-background/50 px-2.5 py-1.5 text-xs text-text placeholder:text-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50" />
		</div>
		<div class="flex-1 overflow-y-auto">
			{#if friendSearch.trim().length >= 2}
				<div class="px-3 py-2">
					<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Search Results</div>
					{#if friendSearchLoading}
						<div class="text-xs text-text-muted py-2 text-center">Searching…</div>
					{:else if $searchResultsStore.length === 0}
						<div class="text-xs text-text-muted py-2 text-center">No users found</div>
					{:else}
						{#each $searchResultsStore as user}
							<div class="flex items-center justify-between rounded-lg px-2 py-1.5 hover:bg-surface-light/30 transition">
								<div>
									<div class="text-xs font-medium text-text">{user.username}</div>
									<div class="text-[10px] text-text-muted/50 font-mono">{user.pubkey.slice(0, 12)}…</div>
								</div>
								{#if user.pubkey === $identityStore.pubkey}
									<span class="text-xs text-text-muted/40">You</span>
								{:else if $friendsStore.some(f => f.pubkey === user.pubkey)}
									<span class="text-xs text-accent">✓</span>
								{:else}
									<button onclick={() => addFriend(user.pubkey, user.username)}
										class="rounded bg-primary/15 px-2 py-0.5 text-xs text-primary hover:bg-primary/25 transition">Add</button>
								{/if}
							</div>
						{/each}
					{/if}
				</div>
			{/if}
			<div class="px-3 py-2">
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Your Friends</div>
				{#if $friendsStore.length === 0}
					<div class="text-xs text-text-muted py-3 text-center">No friends yet</div>
				{:else}
					{#each $friendsStore as friend}
						<div class="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-light/30 transition">
							<button onclick={() => { selectConversation(friend.pubkey); upsertConversation({ id: friend.pubkey, name: displayName(friend.pubkey), type: 'dm', unreadCount: 0 }); }}
								class="flex items-center gap-2 flex-1 min-w-0 text-left">
								<div class="w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-xs text-primary font-bold flex-shrink-0">
									{(friend.username || friend.pubkey)[0]?.toUpperCase()}
								</div>
								<div class="min-w-0 flex-1">
									<div class="text-xs font-medium text-text truncate">{friend.username || friend.pubkey.slice(0, 12) + '…'}</div>
								</div>
							</button>
							<button onclick={() => removeFriend(friend.pubkey)} class="text-text-muted/30 hover:text-danger transition p-0.5" title="Remove">
								<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
							</button>
						</div>
					{/each}
				{/if}
			</div>
		</div>

	<!-- ═══════════ CHANNEL ═══════════ -->
	{:else if activeView.startsWith('channel:')}
		<div class="px-3 py-3 border-b border-surface-light/20">
			<h2 class="text-sm font-bold text-text truncate">{activeChannel?.name || 'Channel'}</h2>
		</div>
		<div class="flex-1 overflow-y-auto py-1">
			<!-- General -->
			<button onclick={() => { if (activeChannelId) activeConversationStore.set(activeChannelId); activeSubChannelStore.set(null); }}
				class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition
					{$activeSubChannelStore === null ? 'bg-primary/15 text-primary font-medium' : 'text-text-muted hover:text-text hover:bg-surface-light/40'}">
				<span class="text-text-muted/50">#</span> general
			</button>

			{#each categories as cat}
				{@const subs = grouped.get(cat) || []}
				{#if subs.length > 0}
					{#if cat !== ''}
						<button onclick={() => { const n = new Set(collapsedCats); if (n.has(cat)) n.delete(cat); else n.add(cat); collapsedCats = n; }}
							class="w-full flex items-center gap-1 px-2 pt-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-text-muted/50 hover:text-text-muted transition">
							<svg class="h-2.5 w-2.5 transition-transform {collapsedCats.has(cat) ? '' : 'rotate-90'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
							</svg>
							{cat}
						</button>
					{/if}
					{#if !collapsedCats.has(cat)}
						{#each subs as sub}
							{#if sub.kind === 'text'}
								<button onclick={() => { if (activeChannelId) activeConversationStore.set(activeChannelId); activeSubChannelStore.set(sub.id); }}
									class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition
										{$activeSubChannelStore === sub.id ? 'bg-primary/15 text-primary font-medium' : 'text-text-muted hover:text-text hover:bg-surface-light/40'}">
									<span class="text-text-muted/50">#</span>
									<span class="truncate">{sub.name}</span>
								</button>
							{:else}
								<button onclick={() => { if (activeChannelId) { joinVoice(activeChannelId).catch(e => addToast(`${e}`, 'error')); activeSubChannelStore.set(sub.id); } }}
									class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition group
										{$activeSubChannelStore === sub.id ? 'bg-accent/15 text-accent font-medium' : 'text-text-muted hover:text-text hover:bg-surface-light/40'}">
									<svg class="h-3.5 w-3.5 text-text-muted/50 group-hover:text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
									</svg>
									<span class="truncate">{sub.name}</span>
									{#if $channelVoiceStore.channelId === activeChannelId && $channelVoiceStore.participants.length > 0}
										<span class="ml-auto text-[10px] text-accent">{$channelVoiceStore.participants.length}</span>
									{/if}
								</button>
							{/if}
						{/each}
					{/if}
				{/if}
			{/each}
		</div>

	<!-- ═══════════ CREATE / JOIN ═══════════ -->
	{:else if activeView === 'create'}
		<div class="px-3 py-3 border-b border-surface-light/20">
			<h2 class="text-sm font-bold text-text">Channels</h2>
		</div>
		<div class="flex-1 overflow-y-auto p-3 space-y-4">
			<!-- Create -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-2">Create Channel</div>
				<input type="text" bind:value={channelName} placeholder="Channel name"
					onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') createChannel(); }}
					class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-2" />
				<button onclick={createChannel} disabled={!channelName.trim() || creating}
					class="w-full rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary/90 transition disabled:opacity-50">
					{creating ? 'Creating…' : 'Create'}
				</button>
			</div>
			<!-- Join -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-2">Join Channel</div>
				<input type="text" bind:value={joinId} placeholder="Channel ID or invite link"
					class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-1.5" />
				<input type="text" bind:value={joinName} placeholder="Display name (optional)"
					class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-1.5" />
				<input type="password" bind:value={joinPassword} placeholder="Password (if required)"
					class="w-full rounded-lg bg-background/50 px-3 py-1.5 text-xs text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 mb-2" />
				<button onclick={joinChannel} disabled={!joinId.trim()}
					class="w-full rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white hover:bg-accent/90 transition disabled:opacity-50">
					Join
				</button>
			</div>
		</div>

	<!-- ═══════════ SETTINGS ═══════════ -->
	{:else if activeView === 'settings'}
		<div class="px-3 py-3 border-b border-surface-light/20">
			<h2 class="text-sm font-bold text-text">Settings</h2>
		</div>
		<div class="flex-1 overflow-y-auto p-3 space-y-4">
			<!-- Username -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Username</div>
				{#if $usernameStore}
					<div class="text-sm text-text">{$usernameStore}</div>
				{:else}
					<div class="flex gap-1.5">
						<input type="text" bind:value={newUsername} placeholder="Choose a username…" maxlength="32"
							onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') setUsername(); }}
							class="flex-1 rounded-lg bg-background/50 px-2.5 py-1.5 text-xs text-text outline-none ring-1 ring-surface-light/30 focus:ring-primary/50" />
						<button onclick={setUsername} disabled={!newUsername.trim() || settingUsername}
							class="rounded-lg bg-primary px-2.5 py-1.5 text-xs font-medium text-white hover:bg-primary/90 transition disabled:opacity-50">
							{settingUsername ? '…' : 'Set'}
						</button>
					</div>
					{#if usernameError}<div class="text-xs text-danger mt-1">{usernameError}</div>{/if}
				{/if}
			</div>
			<!-- Identity -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Public Key</div>
				<div class="text-[10px] text-text-muted font-mono break-all">{$identityStore.pubkey || '—'}</div>
			</div>
			<!-- Theme -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Theme</div>
				{#if $isDarkModeUnlocked}
					<div class="flex gap-2">
						<button onclick={() => themeStore.set('light')}
							class="flex-1 rounded-lg px-3 py-1.5 text-xs transition {$themeStore === 'light' ? 'bg-primary/20 text-primary font-medium' : 'bg-surface-light/30 text-text-muted'}">Light</button>
						<button onclick={() => themeStore.set('dark')}
							class="flex-1 rounded-lg px-3 py-1.5 text-xs transition {$themeStore === 'dark' ? 'bg-primary/20 text-primary font-medium' : 'bg-surface-light/30 text-text-muted'}">Dark</button>
					</div>
				{:else}
					<div class="text-xs text-text-muted/60">🔒 Dark mode is a supporter perk</div>
				{/if}
			</div>
			<!-- Supporter -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Supporter</div>
				{#if $featureStore.tier === 'supporter'}
					<div class="flex items-center gap-2">
						<span class="text-xs text-accent">✦ Supporter</span>
						<button onclick={resetFeatures} class="text-xs text-text-muted hover:text-danger transition">Reset</button>
					</div>
				{:else}
					<div class="flex gap-1.5">
						<input type="password" bind:value={redeemInput} placeholder="Redeem key…"
							onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') tryRedeem(); }}
							class="flex-1 rounded-lg bg-background/50 px-2.5 py-1 text-xs text-text outline-none ring-1 ring-surface-light/30 focus:ring-primary/50" />
						<button onclick={tryRedeem} class="rounded-lg bg-primary/15 px-2.5 py-1 text-xs text-primary hover:bg-primary/25 transition">Unlock</button>
					</div>
					{#if redeemError}<div class="text-xs text-danger mt-1">{redeemError}</div>{/if}
				{/if}
			</div>
			<!-- NSFW filter -->
			<div>
				<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50 mb-1">Content Filter</div>
				<div class="text-xs text-text-muted/60">NSFW filter is enabled by default</div>
			</div>
			<!-- Lock -->
			<button onclick={async () => {
				try { await invoke('lock_profile'); onlock(); }
				catch (e) { console.error(e); }
			}} class="w-full rounded-lg bg-danger/15 border border-danger/20 px-3 py-1.5 text-xs text-danger hover:bg-danger/25 transition flex items-center justify-center gap-1.5">
				<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
				</svg>
				Lock Profile
			</button>
		</div>
	{/if}
</div>
