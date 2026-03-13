<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { feedStore, friendsStore, identityStore, addToast, profilesStore } from '$lib/stores';
	import PostCard from './PostCard.svelte';
	import PostComposer from './PostComposer.svelte';

	let {
		onprofile,
	}: {
		onprofile?: (pubkey: string) => void;
	} = $props();

	let showComposer = $state(false);
	let loading = $state(false);

	async function loadFeed() {
		loading = true;
		try {
			const friendPks = $friendsStore.map(f => f.pubkey);
			await invoke('get_feed', { friendPubkeys: friendPks, limit: 30 });
		} catch (e) {
			console.error('Failed to load feed:', e);
		}
		loading = false;
	}

	// Load feed on mount and load profiles for post authors
	$effect(() => {
		loadFeed();
	});

	// Fetch profiles for feed authors we don't know yet
	$effect(() => {
		const authors = new Set($feedStore.map(p => p.authorPubkey));
		for (const pk of authors) {
			if (!$profilesStore.has(pk)) {
				invoke('get_profile', { pubkey: pk }).catch(() => {});
			}
		}
	});
</script>

<div class="flex h-full flex-col overflow-hidden">
	<!-- Header -->
	<div class="flex items-center justify-between border-b border-surface-light/20 px-5 py-3">
		<h2 class="text-sm font-bold text-text">Feed</h2>
		<div class="flex gap-2">
			<button onclick={loadFeed} disabled={loading}
				class="rounded-lg px-2.5 py-1 text-xs text-text-muted hover:text-text hover:bg-surface-light/30 transition disabled:opacity-50"
				title="Refresh">
				<svg class="h-4 w-4 {loading ? 'animate-spin' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
				</svg>
			</button>
			<button onclick={() => showComposer = !showComposer}
				class="rounded-lg bg-primary px-3 py-1 text-xs font-medium text-white hover:bg-primary/90 transition">
				{showComposer ? 'Cancel' : '+ Post'}
			</button>
		</div>
	</div>

	<!-- Composer -->
	{#if showComposer}
		<PostComposer onpost={() => { showComposer = false; loadFeed(); }} />
	{/if}

	<!-- Posts -->
	<div class="flex-1 overflow-y-auto px-5 py-3 space-y-3">
		{#if $feedStore.length === 0 && !loading}
			<div class="text-center py-12">
				<div class="text-3xl opacity-20 mb-3">✦</div>
				<div class="text-sm text-text-muted/60">Your feed is empty</div>
				<div class="text-xs text-text-muted/40 mt-1">Add friends to see their posts here</div>
			</div>
		{:else}
			{#each $feedStore as post}
				<PostCard {post} {onprofile} />
			{/each}
		{/if}
	</div>
</div>
