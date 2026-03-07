<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { activeConversationStore, upsertConversation, nicknamesStore, identityStore, friendsStore, addToast } from '$lib/stores';
	import { displayName } from '$lib/stores';

	interface ChannelMember {
		pubkey: string;
		nickname: string | null;
		isSelf: boolean;
	}

	let { channelId, onclose }: { channelId: string; onclose: () => void } = $props();

	let members = $state<ChannelMember[]>([]);
	let loading = $state(true);
	let editingNickname = $state<string | null>(null);
	let nicknameInput = $state('');
	let copiedPubkey = $state<string | null>(null);
	/** Pubkey of the member whose action menu is open */
	let actionMenuOpen = $state<string | null>(null);

	let retryTimer: ReturnType<typeof setTimeout> | null = null;

	$effect(() => {
		if (channelId) {
			loadMembers();
		}
		return () => {
			if (retryTimer) clearTimeout(retryTimer);
		};
	});

	// Close action menu on outside click
	function handleWindowClick() {
		if (actionMenuOpen) actionMenuOpen = null;
	}

	async function loadMembers() {
		loading = true;
		try {
			const result = await invoke<ChannelMember[]>('get_channel_members', { channelId });
			members = result;
			if (result.length === 0 && retryTimer === null) {
				retryTimer = setTimeout(async () => {
					retryTimer = null;
					try {
						const retry = await invoke<ChannelMember[]>('get_channel_members', { channelId });
						if (retry.length > 0) members = retry;
					} catch (_) { /* ignore */ }
				}, 2000);
			}
		} catch (e) {
			console.error('Failed to load members:', e);
			members = [];
		}
		loading = false;
	}

	function getMemberDisplayName(member: ChannelMember): string {
		// Priority: local nickname > username (from friends/member) > truncated pubkey
		const localNick = $nicknamesStore.get(member.pubkey);
		if (localNick) return localNick;
		// Check friends list for username
		const friend = $friendsStore.find(f => f.pubkey === member.pubkey);
		if (friend?.username) return friend.username;
		if (member.nickname) return member.nickname;
		return member.pubkey.length > 16
			? `${member.pubkey.substring(0, 8)}…${member.pubkey.substring(member.pubkey.length - 8)}`
			: member.pubkey;
	}

	function truncatePubkey(pk: string): string {
		if (pk.length <= 16) return pk;
		return `${pk.substring(0, 8)}…${pk.substring(pk.length - 8)}`;
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
			members = members.map(m =>
				m.pubkey === pubkey ? { ...m, nickname: nick } : m
			);
		} catch (e) {
			console.error('Failed to save nickname:', e);
		}
		editingNickname = null;
		nicknameInput = '';
	}

	function startDm(pubkey: string) {
		upsertConversation({
			id: pubkey,
			name: displayName(pubkey),
			type: 'dm',
			unreadCount: 0,
		});
		activeConversationStore.set(pubkey);
		actionMenuOpen = null;
		onclose();
	}

	async function addAsFriend(pubkey: string, name: string | null) {
		try {
			await invoke('add_friend', { pubkey, username: name });
			// Refresh local friends store
			const list: [string, string | null][] = await invoke('get_friends');
			friendsStore.set(list.map(([pk, un]) => ({ pubkey: pk, username: un })));
			addToast('Added to friends', 'success');
		} catch (e) {
			console.error('Failed to add friend:', e);
			addToast('Failed to add friend', 'error');
		}
		actionMenuOpen = null;
	}

	async function startCall(pubkey: string) {
		// Open DM and initiate voice
		upsertConversation({
			id: pubkey,
			name: displayName(pubkey),
			type: 'dm',
			unreadCount: 0,
		});
		activeConversationStore.set(pubkey);
		actionMenuOpen = null;
		onclose();
		// DM voice is initiated from Chat.svelte — user clicks the call button there
		addToast('Switched to DM — use the call button to start a voice call', 'info');
	}

	function copyPubkey(pubkey: string) {
		navigator.clipboard.writeText(pubkey);
		copiedPubkey = pubkey;
		setTimeout(() => copiedPubkey = null, 1500);
	}

	function isFriend(pubkey: string): boolean {
		return $friendsStore.some(f => f.pubkey === pubkey);
	}

	function toggleActionMenu(e: MouseEvent, pubkey: string) {
		e.stopPropagation();
		actionMenuOpen = actionMenuOpen === pubkey ? null : pubkey;
	}
</script>

<svelte:window onclick={handleWindowClick} />

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="flex items-center justify-between border-b border-surface-light px-4 py-3">
		<h3 class="text-sm font-semibold text-text">Members ({members.length})</h3>
		<div class="flex items-center gap-1">
			<button
				onclick={loadMembers}
				class="rounded p-1 text-text-muted hover:text-text transition"
				title="Refresh members"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
				</svg>
			</button>
			<button
				onclick={onclose}
				class="rounded p-1 text-text-muted hover:text-text transition"
				title="Close member list"
			>
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>
	</div>

	<!-- Member List -->
	<div class="flex-1 overflow-y-auto">
		{#if loading}
			<div class="p-4 text-center text-sm text-text-muted">Loading members…</div>
		{:else if members.length === 0}
			<div class="p-4 text-center text-sm text-text-muted">No members found. Try again after connecting.</div>
		{:else}
			{#each members as member}
				<div class="group relative border-b border-surface-light/30 px-4 py-2.5 hover:bg-surface-light/40 transition">
					<div class="flex items-center gap-2.5">
						<!-- Avatar -->
						<div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-sm flex-shrink-0">
							{#if member.isSelf}
								<span class="text-primary font-bold text-xs">You</span>
							{:else}
								<span class="text-primary/70 font-medium">{getMemberDisplayName(member).charAt(0).toUpperCase()}</span>
							{/if}
						</div>

						<!-- Name (clickable for non-self members) -->
						<div class="min-w-0 flex-1">
							{#if editingNickname === member.pubkey}
								<div class="flex items-center gap-1">
									<input
										type="text"
										bind:value={nicknameInput}
										onkeydown={(e: KeyboardEvent) => {
											if (e.key === 'Enter') saveNickname(member.pubkey);
											if (e.key === 'Escape') { editingNickname = null; }
										}}
										placeholder="Set nickname…"
										class="text-xs bg-background rounded px-2 py-0.5 text-text outline-none ring-1 ring-surface-light focus:ring-primary w-28"
									/>
									<button onclick={() => saveNickname(member.pubkey)} class="text-xs text-primary hover:text-primary/80">Save</button>
									<button onclick={() => { editingNickname = null; }} class="text-xs text-text-muted hover:text-text">Cancel</button>
								</div>
							{:else}
								<!-- svelte-ignore a11y_no_static_element_interactions -->
								<button
									onclick={(e: MouseEvent) => {
										if (!member.isSelf) toggleActionMenu(e, member.pubkey);
									}}
									class="text-sm font-medium truncate block max-w-full text-left transition {member.isSelf ? 'text-text cursor-default' : 'text-text hover:text-primary cursor-pointer'}"
									disabled={member.isSelf}
								>
									{getMemberDisplayName(member)}
									{#if member.isSelf}
										<span class="text-xs text-text-muted ml-1">(you)</span>
									{/if}
								</button>
								<button
									onclick={() => copyPubkey(member.pubkey)}
									class="text-xs text-text-muted/50 hover:text-text-muted transition truncate block"
									title="Click to copy public key"
								>
									{copiedPubkey === member.pubkey ? '✓ Copied!' : truncatePubkey(member.pubkey)}
								</button>
							{/if}
						</div>

						<!-- Friend indicator -->
						{#if !member.isSelf && isFriend(member.pubkey)}
							<span class="text-xs text-accent flex-shrink-0" title="Friend">★</span>
						{/if}
					</div>

					<!-- Action Menu Popover -->
					{#if actionMenuOpen === member.pubkey && !member.isSelf}
						<!-- svelte-ignore a11y_no_static_element_interactions -->
						<div
							class="absolute right-3 top-full -mt-1 z-50 w-44 rounded-lg border border-surface-light bg-surface shadow-lg overflow-hidden"
							onclick={(e: MouseEvent) => e.stopPropagation()}
						>
							<!-- Send Message -->
							<button
								onclick={() => startDm(member.pubkey)}
								class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-text hover:bg-surface-light/60 transition text-left"
							>
								<svg class="h-3.5 w-3.5 text-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
								</svg>
								Send Message
							</button>

							<!-- Add Friend / Already Friend -->
							{#if isFriend(member.pubkey)}
								<div class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-accent">
									<svg class="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 24 24">
										<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
									</svg>
									Already a Friend
								</div>
							{:else}
								<button
									onclick={() => addAsFriend(member.pubkey, getMemberDisplayName(member))}
									class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-text hover:bg-surface-light/60 transition text-left"
								>
									<svg class="h-3.5 w-3.5 text-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
									</svg>
									Add Friend
								</button>
							{/if}

							<!-- Start Call -->
							<button
								onclick={() => startCall(member.pubkey)}
								class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-text hover:bg-surface-light/60 transition text-left"
							>
								<svg class="h-3.5 w-3.5 text-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
								</svg>
								Start Call
							</button>

							<div class="border-t border-surface-light/40"></div>

							<!-- Set Nickname -->
							<button
								onclick={() => { editingNickname = member.pubkey; nicknameInput = getMemberDisplayName(member); actionMenuOpen = null; }}
								class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-text-muted hover:bg-surface-light/60 transition text-left"
							>
								<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
								</svg>
								Set Nickname
							</button>

							<!-- Copy Pubkey -->
							<button
								onclick={() => { copyPubkey(member.pubkey); actionMenuOpen = null; }}
								class="flex w-full items-center gap-2.5 px-3 py-2 text-xs text-text-muted hover:bg-surface-light/60 transition text-left"
							>
								<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
								</svg>
								Copy Public Key
							</button>
						</div>
					{/if}
				</div>
			{/each}
		{/if}
	</div>
</div>
