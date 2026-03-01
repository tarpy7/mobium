<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { activeConversationStore, upsertConversation, nicknamesStore, displayName } from '$lib/stores';

	interface ChannelMember {
		pubkey: string;
		nickname: string | null;
		isSelf: boolean;
	}

	let { onclose }: { onclose: () => void } = $props();

	let users = $state<ChannelMember[]>([]);
	let loading = $state(true);
	let searchQuery = $state('');
	let editingNickname = $state<string | null>(null);
	let nicknameInput = $state('');
	let copiedPubkey = $state<string | null>(null);

	const filteredUsers = $derived(
		users.filter(u => {
			const name = (u.nickname || u.pubkey).toLowerCase();
			return name.includes(searchQuery.toLowerCase());
		})
	);

	$effect(() => {
		loadUsers();
	});

	async function loadUsers() {
		loading = true;
		try {
			const result = await invoke<ChannelMember[]>('get_all_known_users');
			users = result;
		} catch (e) {
			console.error('Failed to load users:', e);
			users = [];
		}
		loading = false;
	}

	function truncatePubkey(pk: string): string {
		if (pk.length <= 16) return pk;
		return `${pk.substring(0, 8)}...${pk.substring(pk.length - 8)}`;
	}

	async function saveNickname(pubkey: string) {
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
			users = users.map(u =>
				u.pubkey === pubkey ? { ...u, nickname: nick } : u
			);
		} catch (e) {
			console.error('Failed to save nickname:', e);
		}
		editingNickname = null;
		nicknameInput = '';
	}

	let initializingDm = $state<string | null>(null);

	async function startDm(pubkey: string) {
		// Immediately show the conversation
		upsertConversation({
			id: pubkey,
			name: displayName(pubkey),
			type: 'dm',
			unreadCount: 0,
		});
		activeConversationStore.set(pubkey);

		// Perform X3DH key exchange in the background so the session
		// is ready before either party sends a message
		initializingDm = pubkey;
		try {
			const result = await invoke<string>('init_dm_session', { recipient: pubkey });
			console.log('[UserList] DM session init:', result);
		} catch (e) {
			console.warn('[UserList] DM session init failed (will retry on first message):', e);
			// Not fatal — X3DH will happen on first send_message if this fails
		}
		initializingDm = null;
		onclose();
	}

	function copyPubkey(pubkey: string, event: MouseEvent) {
		event.stopPropagation();
		navigator.clipboard.writeText(pubkey);
		copiedPubkey = pubkey;
		setTimeout(() => copiedPubkey = null, 1500);
	}
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="border-b border-surface-light px-4 py-3">
		<div class="flex items-center justify-between mb-2">
			<h3 class="text-sm font-semibold text-text">People ({users.length})</h3>
			<div class="flex items-center gap-1">
				<button
					onclick={loadUsers}
					class="rounded p-1 text-text-muted hover:text-text transition"
					title="Refresh"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
					</svg>
				</button>
				<button
					onclick={onclose}
					class="rounded p-1 text-text-muted hover:text-text transition"
					title="Close"
				>
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</button>
			</div>
		</div>
		<!-- Search -->
		<input
			type="text"
			bind:value={searchQuery}
			placeholder="Search people..."
			class="w-full rounded-lg bg-background px-3 py-1.5 text-xs text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
		/>
	</div>

	<!-- User List -->
	<div class="flex-1 overflow-y-auto">
		{#if loading}
			<div class="p-4 text-center text-sm text-text-muted">Loading users...</div>
		{:else if users.length === 0}
			<div class="p-6 text-center text-sm text-text-muted">
				<div class="mb-2 text-2xl opacity-20">👥</div>
				<div>No users found.</div>
				<div class="mt-1 text-xs">Join a channel to discover other users.</div>
			</div>
		{:else if filteredUsers.length === 0}
			<div class="p-4 text-center text-sm text-text-muted">No matches for "{searchQuery}"</div>
		{:else}
			{#each filteredUsers as user}
				{#if editingNickname === user.pubkey}
					<!-- Editing nickname inline -->
					<div class="border-b border-surface-light/50 px-4 py-3 bg-surface-light/30">
						<div class="flex items-center gap-2">
							<div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-sm flex-shrink-0">
								<span class="text-primary/70">{(user.nickname || user.pubkey).charAt(0).toUpperCase()}</span>
							</div>
							<div class="flex-1 flex items-center gap-1">
								<input
									type="text"
									bind:value={nicknameInput}
									onkeydown={(e: KeyboardEvent) => {
										if (e.key === 'Enter') saveNickname(user.pubkey);
										if (e.key === 'Escape') { editingNickname = null; }
									}}
									placeholder="Set nickname..."
									class="text-xs bg-background rounded px-2 py-1 text-text outline-none ring-1 ring-surface-light focus:ring-primary flex-1"
								/>
								<button onclick={() => saveNickname(user.pubkey)} class="text-xs text-primary font-medium px-1">Save</button>
								<button onclick={() => { editingNickname = null; }} class="text-xs text-text-muted px-1">Cancel</button>
							</div>
						</div>
					</div>
				{:else}
					<!-- Clickable user row — opens DM -->
					<div
						role="button"
						tabindex="0"
						onclick={() => startDm(user.pubkey)}
						onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && startDm(user.pubkey)}
						class="group w-full border-b border-surface-light/50 px-4 py-3 text-left transition hover:bg-surface-light/50 cursor-pointer"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2 min-w-0 flex-1">
								<!-- Avatar -->
								<div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-sm flex-shrink-0">
									<span class="text-primary/70">{(user.nickname || user.pubkey).charAt(0).toUpperCase()}</span>
								</div>

								<div class="min-w-0 flex-1">
									<div class="text-sm font-medium text-text truncate">
										{user.nickname || truncatePubkey(user.pubkey)}
									</div>
									<div class="text-xs text-text-muted/60 truncate">
										{truncatePubkey(user.pubkey)}
									</div>
								</div>
							</div>

							<!-- Action buttons (right side) -->
							<div class="flex items-center gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition">
								<button
									onclick={(e: MouseEvent) => { e.stopPropagation(); editingNickname = user.pubkey; nicknameInput = user.nickname || ''; }}
									class="rounded p-1 text-text-muted hover:text-text hover:bg-surface-light transition"
									title="Edit nickname"
								>
									<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
									</svg>
								</button>
								<button
									onclick={(e: MouseEvent) => copyPubkey(user.pubkey, e)}
									class="rounded p-1 text-text-muted hover:text-text hover:bg-surface-light transition"
									title="Copy public key"
								>
									<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
									</svg>
								</button>
							</div>

							<!-- DM indicator / loading spinner -->
							<div class="flex-shrink-0 ml-1 text-text-muted group-hover:text-primary transition">
								{#if initializingDm === user.pubkey}
									<svg class="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
										<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
										<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
									</svg>
								{:else}
									<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
									</svg>
								{/if}
							</div>
						</div>
					</div>
				{/if}
			{/each}
		{/if}
	</div>
</div>
