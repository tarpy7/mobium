<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { profilesStore, userPostsStore, identityStore, friendsStore, displayName, addToast } from '$lib/stores';
	import type { Post, UserProfile } from '$lib/stores';
	import PostCard from './PostCard.svelte';

	let {
		pubkey,
		onclose,
		oncompose,
	}: {
		pubkey: string;
		onclose: () => void;
		oncompose?: () => void;
	} = $props();

	let profile = $derived($profilesStore.get(pubkey));
	let posts = $derived($userPostsStore.get(pubkey) || []);
	let isMe = $derived($identityStore.pubkey === pubkey);
	let isFriend = $derived($friendsStore.some(f => f.pubkey === pubkey));

	// Edit mode
	let editing = $state(false);
	let editName = $state('');
	let editBio = $state('');
	let saving = $state(false);

	$effect(() => {
		if (pubkey) {
			invoke('get_profile', { pubkey }).catch(() => {});
			invoke('get_user_posts', { pubkey, limit: 30 }).catch(() => {});
		}
	});

	function startEdit() {
		editName = profile?.displayName || '';
		editBio = profile?.bio || '';
		editing = true;
	}

	async function saveProfile() {
		saving = true;
		try {
			await invoke('update_profile', {
				displayName: editName.trim(),
				bio: editBio.trim(),
				avatarHash: profile?.avatarHash || '',
				bannerHash: profile?.bannerHash || '',
			});
			editing = false;
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
		saving = false;
	}

	async function toggleFriend() {
		try {
			if (isFriend) {
				await invoke('remove_friend', { pubkey });
			} else {
				await invoke('add_friend', { pubkey, username: profile?.username || null });
			}
			// Reload friends
			const list: [string, string | null][] = await invoke('get_friends');
			friendsStore.set(list.map(([pk, u]) => ({ pubkey: pk, username: u })));
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
	}

	function formatDate(ts: number): string {
		return new Date(ts * 1000).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
	}
</script>

<div class="flex h-full flex-col overflow-hidden">
	<!-- Banner -->
	<div class="relative h-32 flex-shrink-0" style="background: linear-gradient(135deg, #e07a5f 0%, #b8a9c9 40%, #81b29a 100%);">
		<button onclick={onclose} class="absolute top-3 left-3 rounded-full bg-black/30 p-1.5 text-white hover:bg-black/50 transition z-10">
			<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" /></svg>
		</button>
	</div>

	<!-- Profile info -->
	<div class="relative px-5 pb-4 -mt-10">
		<!-- Avatar -->
		<div class="flex h-20 w-20 items-center justify-center rounded-full border-4 border-background bg-surface text-2xl font-bold text-primary">
			{(profile?.displayName || profile?.username || pubkey)[0]?.toUpperCase() || '?'}
		</div>

		<div class="mt-3 flex items-start justify-between">
			<div class="min-w-0 flex-1">
				{#if editing}
					<input type="text" bind:value={editName} placeholder="Display name" maxlength="64"
						class="text-lg font-bold text-text bg-background rounded-lg px-2 py-1 outline-none ring-1 ring-surface-light focus:ring-primary w-full mb-1" />
					<textarea bind:value={editBio} placeholder="Write something about yourself…" maxlength="2048" rows="3"
						class="text-sm text-text bg-background rounded-lg px-2 py-1 outline-none ring-1 ring-surface-light focus:ring-primary w-full resize-none"></textarea>
					<div class="flex gap-2 mt-2">
						<button onclick={saveProfile} disabled={saving}
							class="rounded-lg bg-primary px-3 py-1 text-xs font-medium text-white hover:bg-primary/90 transition disabled:opacity-50">
							{saving ? 'Saving…' : 'Save'}
						</button>
						<button onclick={() => editing = false}
							class="rounded-lg px-3 py-1 text-xs text-text-muted hover:text-text transition">Cancel</button>
					</div>
				{:else}
					<h2 class="text-lg font-bold text-text truncate">{profile?.displayName || displayName(pubkey)}</h2>
					{#if profile?.username}
						<div class="text-xs text-text-muted">@{profile.username}</div>
					{/if}
					{#if profile?.bio}
						<p class="text-sm text-text-muted mt-2 whitespace-pre-wrap">{profile.bio}</p>
					{/if}
				{/if}
			</div>

			{#if !editing}
				<div class="flex gap-2 flex-shrink-0 ml-3">
					{#if isMe}
						<button onclick={startEdit}
							class="rounded-lg border border-surface-light/50 px-3 py-1.5 text-xs font-medium text-text hover:bg-surface-light/30 transition">
							Edit Profile
						</button>
						{#if oncompose}
							<button onclick={oncompose}
								class="rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-white hover:bg-primary/90 transition">
								New Post
							</button>
						{/if}
					{:else}
						<button onclick={toggleFriend}
							class="rounded-lg px-3 py-1.5 text-xs font-medium transition
								{isFriend ? 'border border-danger/30 text-danger hover:bg-danger/10' : 'bg-primary text-white hover:bg-primary/90'}">
							{isFriend ? 'Remove Friend' : 'Add Friend'}
						</button>
					{/if}
				</div>
			{/if}
		</div>
	</div>

	<!-- Posts -->
	<div class="border-t border-surface-light/30 px-5 py-3">
		<div class="text-[10px] font-bold uppercase tracking-wider text-text-muted/50">Posts</div>
	</div>
	<div class="flex-1 overflow-y-auto px-5 pb-4 space-y-3">
		{#if posts.length === 0}
			<div class="text-center text-sm text-text-muted/50 py-8">
				{isMe ? "You haven't posted anything yet" : 'No posts yet'}
			</div>
		{:else}
			{#each posts as post}
				<PostCard {post} showAuthor={false} />
			{/each}
		{/if}
	</div>
</div>
