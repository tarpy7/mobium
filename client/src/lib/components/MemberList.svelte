<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { activeConversationStore, upsertConversation, nicknamesStore, identityStore } from '$lib/stores';
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

	let retryTimer: ReturnType<typeof setTimeout> | null = null;

	$effect(() => {
		if (channelId) {
			loadMembers();
		}
		return () => {
			if (retryTimer) clearTimeout(retryTimer);
		};
	});

	async function loadMembers() {
		loading = true;
		try {
			const result = await invoke<ChannelMember[]>('get_channel_members', { channelId });
			members = result;
			// If empty, the server may still be responding — retry after a delay
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
			// Update local member list
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
		// Create a DM conversation and switch to it
		upsertConversation({
			id: pubkey,
			name: displayName(pubkey),
			type: 'dm',
			unreadCount: 0,
		});
		activeConversationStore.set(pubkey);
		onclose();
	}

	function copyPubkey(pubkey: string) {
		navigator.clipboard.writeText(pubkey);
		copiedPubkey = pubkey;
		setTimeout(() => copiedPubkey = null, 1500);
	}
</script>

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
			<div class="p-4 text-center text-sm text-text-muted">Loading members...</div>
		{:else if members.length === 0}
			<div class="p-4 text-center text-sm text-text-muted">No members found. Try again after connecting.</div>
		{:else}
			{#each members as member}
				<div class="group border-b border-surface-light/50 px-4 py-3 hover:bg-surface-light/50 transition">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 min-w-0 flex-1">
							<!-- Avatar -->
							<div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-sm flex-shrink-0">
								{#if member.isSelf}
									<span class="text-primary font-bold text-xs">You</span>
								{:else}
									<span class="text-primary/70">{(member.nickname || member.pubkey).charAt(0).toUpperCase()}</span>
								{/if}
							</div>

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
											placeholder="Set nickname..."
											class="text-xs bg-background rounded px-2 py-0.5 text-text outline-none ring-1 ring-surface-light focus:ring-primary w-24"
										/>
										<button onclick={() => saveNickname(member.pubkey)} class="text-xs text-primary">Save</button>
										<button onclick={() => { editingNickname = null; }} class="text-xs text-text-muted">Cancel</button>
									</div>
								{:else}
									<button
										onclick={() => { editingNickname = member.pubkey; nicknameInput = member.nickname || ''; }}
										class="text-sm font-medium text-text hover:text-primary transition truncate block max-w-full text-left"
										title="Click to edit nickname"
									>
										{member.nickname || truncatePubkey(member.pubkey)}
										{#if member.isSelf}
											<span class="text-xs text-text-muted ml-1">(you)</span>
										{/if}
									</button>
									<button
										onclick={() => copyPubkey(member.pubkey)}
										class="text-xs text-text-muted/60 hover:text-text-muted transition truncate block"
										title="Click to copy full public key"
									>
										{copiedPubkey === member.pubkey ? 'Copied!' : truncatePubkey(member.pubkey)}
									</button>
								{/if}
							</div>
						</div>

						<!-- DM button (not for self) -->
						{#if !member.isSelf}
							<button
								onclick={() => startDm(member.pubkey)}
								class="flex-shrink-0 rounded-lg p-1.5 text-text-muted hover:text-primary hover:bg-primary/10 transition opacity-0 group-hover:opacity-100"
								title="Send direct message"
							>
								<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
								</svg>
							</button>
						{/if}
					</div>
				</div>
			{/each}
		{/if}
	</div>
</div>
