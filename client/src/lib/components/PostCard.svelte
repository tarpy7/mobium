<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { identityStore, displayName, profilesStore, addToast } from '$lib/stores';
	import type { Post } from '$lib/stores';

	let {
		post,
		showAuthor = true,
		onprofile,
	}: {
		post: Post;
		showAuthor?: boolean;
		onprofile?: (pubkey: string) => void;
	} = $props();

	let isMe = $derived($identityStore.pubkey === post.authorPubkey);
	let profile = $derived($profilesStore.get(post.authorPubkey));
	let showActions = $state(false);

	function timeAgo(ts: number): string {
		const s = Math.floor(Date.now() / 1000 - ts);
		if (s < 60) return 'just now';
		if (s < 3600) return `${Math.floor(s / 60)}m`;
		if (s < 86400) return `${Math.floor(s / 3600)}h`;
		if (s < 604800) return `${Math.floor(s / 86400)}d`;
		return new Date(ts * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
	}

	async function deletePost() {
		try {
			await invoke('delete_post', { postId: post.id });
			addToast('Post deleted', 'success');
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
	}

	async function react(emoji: string) {
		try {
			await invoke('react_post', { postId: post.id, emoji });
		} catch (e) { addToast(`Failed: ${e}`, 'error'); }
	}
</script>

<div class="rounded-xl border border-surface-light/30 bg-surface/60 p-4 transition hover:border-surface-light/50">
	<!-- Author row -->
	{#if showAuthor}
		<div class="flex items-center gap-2.5 mb-2.5">
			<button onclick={() => onprofile?.(post.authorPubkey)}
				class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/15 text-sm font-bold text-primary flex-shrink-0 hover:bg-primary/25 transition">
				{(profile?.displayName || displayName(post.authorPubkey))[0]?.toUpperCase() || '?'}
			</button>
			<div class="min-w-0 flex-1">
				<button onclick={() => onprofile?.(post.authorPubkey)}
					class="text-sm font-semibold text-text hover:text-primary transition truncate block">
					{profile?.displayName || displayName(post.authorPubkey)}
				</button>
				{#if profile?.username}
					<span class="text-[10px] text-text-muted">@{profile.username}</span>
				{/if}
			</div>
			<span class="text-[10px] text-text-muted/50 flex-shrink-0">{timeAgo(post.createdAt)}</span>
		</div>
	{:else}
		<div class="flex items-center justify-end mb-1">
			<span class="text-[10px] text-text-muted/50">{timeAgo(post.createdAt)}</span>
		</div>
	{/if}

	<!-- Content -->
	<div class="text-sm text-text whitespace-pre-wrap break-words">{post.content}</div>

	<!-- Media indicator -->
	{#if post.mediaHash}
		<div class="mt-2 rounded-lg bg-surface-light/30 px-3 py-2 text-xs text-text-muted flex items-center gap-2">
			{#if post.mediaType?.startsWith('image/')}
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
				Image
			{:else if post.mediaType?.startsWith('video/')}
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
				Video
			{:else}
				📎 Attachment
			{/if}
			{#if post.mediaSize}
				<span class="text-text-muted/40">({(post.mediaSize / 1024).toFixed(0)} KB)</span>
			{/if}
		</div>
	{/if}

	<!-- Visibility badge + actions -->
	<div class="flex items-center justify-between mt-3">
		<div class="flex items-center gap-2">
			<span class="text-[10px] px-1.5 py-0.5 rounded-full {post.visibility === 'public' ? 'bg-accent/15 text-accent' : post.visibility === 'friends' ? 'bg-primary/15 text-primary' : 'bg-surface-light/40 text-text-muted'}">
				{post.visibility === 'public' ? '🌐 Public' : post.visibility === 'friends' ? '👥 Friends' : '🔒 Private'}
			</span>
		</div>
		<div class="flex items-center gap-1">
			<button onclick={() => react('❤️')} class="rounded p-1 text-text-muted/40 hover:text-danger hover:bg-danger/10 transition" title="Like">
				<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" /></svg>
			</button>
			{#if isMe}
				<button onclick={deletePost} class="rounded p-1 text-text-muted/40 hover:text-danger hover:bg-danger/10 transition" title="Delete">
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
				</button>
			{/if}
		</div>
	</div>
</div>
