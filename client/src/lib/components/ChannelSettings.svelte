<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { subChannelsStore, bansStore, addToast, activeSubChannelStore } from '$lib/stores';
	import type { SubChannel } from '$lib/stores';

	let {
		channelId,
		isOwner,
		isMod,
		onclose,
	}: {
		channelId: string;
		isOwner: boolean;
		isMod: boolean;
		onclose: () => void;
	} = $props();

	let tab = $state<'rooms' | 'bans' | 'settings'>('rooms');
	let newRoomName = $state('');
	let newRoomKind = $state<'text' | 'voice'>('text');
	let newRoomCategory = $state('');
	let passwordInput = $state('');
	let showPasswordField = $state(false);
	let loadingBans = $state(false);

	let subChannels = $derived($subChannelsStore.get(channelId) || []);

	$effect(() => {
		if (channelId) {
			invoke('get_sub_channels', { channelId }).catch(() => {});
		}
	});

	async function createRoom() {
		const name = newRoomName.trim();
		if (!name) return;
		if (name.length > 64) { addToast('Name too long (max 64)', 'error'); return; }
		try {
			await invoke('create_sub_channel', { channelId, name, kind: newRoomKind, category: newRoomCategory.trim() || null });
			newRoomName = '';
			newRoomCategory = '';
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}

	async function deleteRoom(subId: string) {
		try {
			await invoke('delete_sub_channel', { channelId, subChannelId: subId });
			// If we were viewing this sub-channel, go back to main
			if ($activeSubChannelStore === subId) activeSubChannelStore.set(null);
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}

	async function loadBans() {
		loadingBans = true;
		try {
			await invoke('get_bans', { channelId });
		} catch (e) {
			addToast(`Failed to load bans: ${e}`, 'error');
		}
		loadingBans = false;
	}

	async function unban(pubkey: string) {
		try {
			await invoke('unban_user', { channelId, targetPubkey: pubkey });
			bansStore.update(b => b.filter(x => x.pubkey !== pubkey));
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}

	async function setPassword() {
		try {
			await invoke('set_channel_password', { channelId, password: passwordInput });
			passwordInput = '';
			showPasswordField = false;
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}

	async function clearPassword() {
		try {
			await invoke('set_channel_password', { channelId, password: '' });
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}

	function selectSubChannel(sub: SubChannel) {
		activeSubChannelStore.set(sub.id);
		onclose();
	}
</script>

<div class="flex h-full flex-col">
	<!-- Header -->
	<div class="flex items-center justify-between border-b border-surface-light px-4 py-3">
		<h3 class="text-sm font-semibold text-text">Channel Settings</h3>
		<button onclick={onclose} class="rounded p-1 text-text-muted hover:text-text transition" title="Close">
			<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
			</svg>
		</button>
	</div>

	<!-- Tabs -->
	<div class="flex border-b border-surface-light/50">
		<button onclick={() => tab = 'rooms'}
			class="flex-1 py-2 text-xs font-medium transition {tab === 'rooms' ? 'text-primary border-b-2 border-primary' : 'text-text-muted hover:text-text'}">
			Rooms
		</button>
		{#if isMod}
			<button onclick={() => { tab = 'bans'; loadBans(); }}
				class="flex-1 py-2 text-xs font-medium transition {tab === 'bans' ? 'text-primary border-b-2 border-primary' : 'text-text-muted hover:text-text'}">
				Bans
			</button>
		{/if}
		{#if isOwner}
			<button onclick={() => tab = 'settings'}
				class="flex-1 py-2 text-xs font-medium transition {tab === 'settings' ? 'text-primary border-b-2 border-primary' : 'text-text-muted hover:text-text'}">
				Security
			</button>
		{/if}
	</div>

	<div class="flex-1 overflow-y-auto">
		<!-- Rooms tab -->
		{#if tab === 'rooms'}
			<div class="p-3 space-y-3">
				<!-- Main channel -->
				<button
					onclick={() => { activeSubChannelStore.set(null); onclose(); }}
					class="w-full flex items-center gap-2 rounded-lg px-3 py-2 text-left text-xs hover:bg-surface-light/50 transition {$activeSubChannelStore === null ? 'bg-surface-light text-primary font-medium' : 'text-text'}"
				>
					<span class="text-sm">💬</span>
					General
				</button>

				<!-- Sub-channels -->
				{#each subChannels as sub}
					<div class="flex items-center gap-1">
						<button
							onclick={() => selectSubChannel(sub)}
							class="flex-1 flex items-center gap-2 rounded-lg px-3 py-2 text-left text-xs hover:bg-surface-light/50 transition {$activeSubChannelStore === sub.id ? 'bg-surface-light text-primary font-medium' : 'text-text'}"
						>
							<span class="text-sm">{sub.kind === 'voice' ? '🔊' : '💬'}</span>
							{sub.name}
							<span class="text-text-muted/40 text-xs ml-auto">{sub.kind}</span>
						</button>
						{#if isMod}
							<button
								onclick={() => deleteRoom(sub.id)}
								class="rounded p-1 text-text-muted/30 hover:text-danger transition"
								title="Delete room"
							>
								<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
									<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
								</svg>
							</button>
						{/if}
					</div>
				{/each}

				<!-- Create room (owner/mod only) -->
				{#if isMod}
					<div class="border-t border-surface-light/40 pt-3">
						<div class="text-xs text-text-muted mb-2">Create Room</div>
						<div class="flex gap-1.5">
							<input type="text" bind:value={newRoomName} placeholder="Room name…" maxlength="64"
								onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') createRoom(); }}
								class="flex-1 rounded-lg bg-background px-2.5 py-1.5 text-xs text-text outline-none ring-1 ring-surface-light focus:ring-primary" />
							<select bind:value={newRoomKind} class="rounded-lg bg-background px-2 py-1.5 text-xs text-text outline-none ring-1 ring-surface-light">
								<option value="text">💬 Text</option>
								<option value="voice">🔊 Voice</option>
							</select>
						</div>
						<input type="text" bind:value={newRoomCategory} placeholder="Category (optional)"
							class="mt-1.5 w-full rounded-lg bg-background px-2.5 py-1.5 text-xs text-text outline-none ring-1 ring-surface-light focus:ring-primary" />
						<button onclick={createRoom} disabled={!newRoomName.trim()}
							class="mt-2 w-full rounded-lg bg-primary/15 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/25 transition disabled:opacity-40">
							Create Room
						</button>
					</div>
				{/if}
			</div>
		{/if}

		<!-- Bans tab -->
		{#if tab === 'bans' && isMod}
			<div class="p-3">
				{#if loadingBans}
					<div class="text-xs text-text-muted text-center py-4">Loading…</div>
				{:else if $bansStore.length === 0}
					<div class="text-xs text-text-muted text-center py-4">No banned users</div>
				{:else}
					{#each $bansStore as ban}
						<div class="flex items-center justify-between rounded-lg px-2 py-2 hover:bg-surface-light/40 transition">
							<div>
								<div class="text-xs font-mono text-text">{ban.pubkey.substring(0, 12)}…</div>
								{#if ban.reason}
									<div class="text-xs text-text-muted/60">{ban.reason}</div>
								{/if}
							</div>
							<button
								onclick={() => unban(ban.pubkey)}
								class="rounded-lg bg-accent/15 px-2 py-0.5 text-xs text-accent hover:bg-accent/25 transition"
							>
								Unban
							</button>
						</div>
					{/each}
				{/if}
			</div>
		{/if}

		<!-- Security tab (owner only) -->
		{#if tab === 'settings' && isOwner}
			<div class="p-3 space-y-4">
				<!-- Channel Password -->
				<div>
					<div class="text-xs font-medium text-text mb-1.5">Join Password</div>
					<p class="text-xs text-text-muted/60 mb-2">Require a password to join this channel. Existing members are not affected.</p>
					{#if showPasswordField}
						<div class="flex gap-1.5">
							<input
								type="password"
								bind:value={passwordInput}
								placeholder="Enter password…"
								onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') setPassword(); }}
								class="flex-1 rounded-lg bg-background px-2.5 py-1.5 text-xs text-text outline-none ring-1 ring-surface-light focus:ring-primary"
							/>
							<button onclick={setPassword} disabled={!passwordInput.trim()}
								class="rounded-lg bg-primary/15 px-3 py-1.5 text-xs text-primary hover:bg-primary/25 transition disabled:opacity-40">Set</button>
							<button onclick={() => { showPasswordField = false; passwordInput = ''; }}
								class="rounded-lg px-2 py-1.5 text-xs text-text-muted hover:text-text transition">✕</button>
						</div>
					{:else}
						<div class="flex gap-2">
							<button onclick={() => showPasswordField = true}
								class="rounded-lg bg-primary/15 px-3 py-1.5 text-xs text-primary hover:bg-primary/25 transition">
								Set Password
							</button>
							<button onclick={clearPassword}
								class="rounded-lg bg-surface-light px-3 py-1.5 text-xs text-text-muted hover:text-text transition">
								Clear Password
							</button>
						</div>
					{/if}
				</div>

				<!-- Info -->
				<div class="border-t border-surface-light/40 pt-3">
					<div class="text-xs text-text-muted/60 space-y-1">
						<p>🔐 All messages are end-to-end encrypted with Sender Keys.</p>
						<p>👑 Only you (the owner) can promote moderators and set passwords.</p>
						<p>🛡️ Moderators can create/delete rooms and ban members.</p>
					</div>
				</div>
			</div>
		{/if}
	</div>
</div>
