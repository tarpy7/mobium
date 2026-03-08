<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { subChannelsStore, activeSubChannelStore, channelVoiceStore, addToast } from '$lib/stores';
	import type { SubChannel } from '$lib/stores';
	import { joinVoice, leaveVoice } from '$lib/channelVoice';

	let {
		channelId,
		channelName,
		minimized = false,
		isMod = false,
		ontoggle,
	}: {
		channelId: string;
		channelName: string;
		minimized: boolean;
		isMod: boolean;
		ontoggle: () => void;
	} = $props();

	let subChannels = $derived($subChannelsStore.get(channelId) || []);
	let collapsedCategories = $state<Set<string>>(new Set());

	// Group sub-channels by category
	let grouped = $derived.by(() => {
		const map = new Map<string, SubChannel[]>();
		// Always have a general/uncategorized group
		map.set('', []);
		for (const sub of subChannels) {
			const cat = sub.category || '';
			if (!map.has(cat)) map.set(cat, []);
			map.get(cat)!.push(sub);
		}
		return map;
	});

	let categories = $derived([...grouped.keys()].sort((a, b) => {
		if (a === '') return -1;
		if (b === '') return 1;
		return a.localeCompare(b);
	}));

	let inVoiceSub = $derived(
		$channelVoiceStore.channelId === channelId ? $channelVoiceStore.channelId : null
	);

	// New room form
	let showNewRoom = $state(false);
	let newName = $state('');
	let newKind = $state<'text' | 'voice'>('text');
	let newCategory = $state('');

	$effect(() => {
		if (channelId) {
			invoke('get_sub_channels', { channelId }).catch(() => {});
		}
	});

	function toggleCategory(cat: string) {
		const next = new Set(collapsedCategories);
		if (next.has(cat)) next.delete(cat);
		else next.add(cat);
		collapsedCategories = next;
	}

	function selectSub(sub: SubChannel) {
		if (sub.kind === 'text') {
			activeSubChannelStore.set(sub.id);
		}
	}

	async function joinVoiceSub(sub: SubChannel) {
		try {
			// Voice sub-channels use the parent channel's voice system
			// The sub-channel ID is passed as context
			await joinVoice(channelId);
			activeSubChannelStore.set(sub.id);
		} catch (e) {
			addToast(`Failed to join voice: ${e}`, 'error');
		}
	}

	async function createRoom() {
		const name = newName.trim();
		if (!name) return;
		try {
			await invoke('create_sub_channel', {
				channelId,
				name,
				kind: newKind,
				category: newCategory.trim() || null,
			});
			newName = '';
			newCategory = '';
			showNewRoom = false;
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
	}
</script>

{#if minimized}
	<!-- Minimized bar -->
	<button
		onclick={ontoggle}
		class="flex items-center gap-2 w-full border-b border-surface-light/30 px-3 py-2 text-xs text-text-muted hover:bg-surface-light/30 transition"
	>
		<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
		</svg>
		<span class="font-medium text-text truncate">{channelName}</span>
		<span class="text-text-muted/50">{subChannels.length} rooms</span>
	</button>
{:else}
	<!-- Full navigation panel -->
	<div class="flex flex-col border-r border-surface-light/30 bg-surface/50 w-52 flex-shrink-0 h-full overflow-hidden">
		<!-- Header -->
		<div class="flex items-center justify-between px-3 py-2.5 border-b border-surface-light/30">
			<h3 class="text-xs font-bold text-text truncate flex-1">{channelName}</h3>
			<button onclick={ontoggle} class="rounded p-0.5 text-text-muted hover:text-text transition" title="Minimize">
				<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
				</svg>
			</button>
		</div>

		<!-- Channel list -->
		<div class="flex-1 overflow-y-auto py-1">
			<!-- General (main channel) -->
			<button
				onclick={() => activeSubChannelStore.set(null)}
				class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition rounded-sm
					{$activeSubChannelStore === null ? 'bg-primary/15 text-primary font-medium' : 'text-text hover:bg-surface-light/40'}"
			>
				<span class="text-text-muted/60">#</span>
				general
			</button>

			{#each categories as cat}
				{@const subs = grouped.get(cat) || []}
				{#if subs.length > 0}
					{#if cat !== ''}
						<!-- Category header -->
						<button
							onclick={() => toggleCategory(cat)}
							class="w-full flex items-center gap-1 px-2 pt-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-text-muted/50 hover:text-text-muted transition"
						>
							<svg class="h-2.5 w-2.5 transition-transform {collapsedCategories.has(cat) ? '' : 'rotate-90'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
							</svg>
							{cat}
						</button>
					{/if}

					{#if !collapsedCategories.has(cat)}
						{#each subs as sub}
							{#if sub.kind === 'text'}
								<button
									onclick={() => selectSub(sub)}
									class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition rounded-sm
										{$activeSubChannelStore === sub.id ? 'bg-primary/15 text-primary font-medium' : 'text-text-muted hover:text-text hover:bg-surface-light/40'}"
								>
									<span class="text-text-muted/50">#</span>
									<span class="truncate">{sub.name}</span>
								</button>
							{:else}
								<!-- Voice channel -->
								<button
									onclick={() => joinVoiceSub(sub)}
									class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left transition rounded-sm group
										{$activeSubChannelStore === sub.id ? 'bg-accent/15 text-accent font-medium' : 'text-text-muted hover:text-text hover:bg-surface-light/40'}"
								>
									<svg class="h-3.5 w-3.5 text-text-muted/50 group-hover:text-accent transition" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h1.586l4.707-4.707C10.923 3.663 12 4.109 12 5v14c0 .891-1.077 1.337-1.707.707L5.586 15z" />
									</svg>
									<span class="truncate">{sub.name}</span>
									{#if $channelVoiceStore.channelId === channelId && $channelVoiceStore.participants.length > 0}
										<span class="ml-auto text-[10px] text-accent">{$channelVoiceStore.participants.length}</span>
									{/if}
								</button>
							{/if}
						{/each}
					{/if}
				{/if}
			{/each}
		</div>

		<!-- Add room button (mod/owner) -->
		{#if isMod}
			{#if showNewRoom}
				<div class="border-t border-surface-light/30 p-2 space-y-1.5 bg-surface-light/20">
					<input type="text" bind:value={newName} placeholder="Room name"
						onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') createRoom(); if (e.key === 'Escape') showNewRoom = false; }}
						class="w-full rounded bg-background px-2 py-1 text-xs text-text outline-none ring-1 ring-surface-light/50 focus:ring-primary" />
					<input type="text" bind:value={newCategory} placeholder="Category (optional)"
						class="w-full rounded bg-background px-2 py-1 text-xs text-text outline-none ring-1 ring-surface-light/50 focus:ring-primary" />
					<div class="flex gap-1">
						<button onclick={() => { newKind = 'text'; }}
							class="flex-1 rounded px-2 py-1 text-xs transition {newKind === 'text' ? 'bg-primary/20 text-primary' : 'bg-surface-light/30 text-text-muted'}">
							# Text
						</button>
						<button onclick={() => { newKind = 'voice'; }}
							class="flex-1 rounded px-2 py-1 text-xs transition {newKind === 'voice' ? 'bg-accent/20 text-accent' : 'bg-surface-light/30 text-text-muted'}">
							🔊 Voice
						</button>
					</div>
					<div class="flex gap-1">
						<button onclick={createRoom} disabled={!newName.trim()}
							class="flex-1 rounded bg-primary/15 px-2 py-1 text-xs text-primary hover:bg-primary/25 transition disabled:opacity-40">Create</button>
						<button onclick={() => showNewRoom = false}
							class="rounded px-2 py-1 text-xs text-text-muted hover:text-text transition">Cancel</button>
					</div>
				</div>
			{:else}
				<button onclick={() => showNewRoom = true}
					class="flex items-center gap-1.5 border-t border-surface-light/30 px-3 py-2 text-xs text-text-muted hover:text-text transition w-full">
					<svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
					</svg>
					Add Room
				</button>
			{/if}
		{/if}
	</div>
{/if}
