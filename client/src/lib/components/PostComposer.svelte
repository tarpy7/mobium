<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { addToast } from '$lib/stores';

	let {
		onpost,
	}: {
		onpost: () => void;
	} = $props();

	let content = $state('');
	let visibility = $state<'friends' | 'public' | 'private'>('friends');
	let posting = $state(false);
	let mediaFile: File | null = $state(null);
	let mediaError = $state('');

	const MAX_VIDEO_DURATION = 15; // seconds

	function handleFileSelect(e: Event) {
		const input = e.target as HTMLInputElement;
		const file = input.files?.[0];
		if (!file) return;
		mediaError = '';

		// Size check (10MB)
		if (file.size > 10 * 1024 * 1024) {
			mediaError = 'File too large (max 10MB)';
			return;
		}

		// Video duration check
		if (file.type.startsWith('video/')) {
			const video = document.createElement('video');
			video.preload = 'metadata';
			video.onloadedmetadata = () => {
				URL.revokeObjectURL(video.src);
				if (video.duration > MAX_VIDEO_DURATION) {
					mediaError = `Video must be ${MAX_VIDEO_DURATION}s or shorter (yours is ${Math.ceil(video.duration)}s)`;
					mediaFile = null;
				} else {
					mediaFile = file;
				}
			};
			video.src = URL.createObjectURL(file);
		} else {
			mediaFile = file;
		}
	}

	async function post() {
		if ((!content.trim() && !mediaFile) || posting) return;
		posting = true;

		try {
			let mediaHash: string | null = null;
			let mediaType: string | null = null;
			let mediaSize: number | null = null;

			// Upload media first if present
			if (mediaFile) {
				const buffer = new Uint8Array(await mediaFile.arrayBuffer());
				mediaType = mediaFile.type;
				mediaSize = mediaFile.size;
				// Upload and get hash back (via event)
				await invoke('upload_media', { data: Array.from(buffer), mimeType: mediaType });
				// TODO: get hash from media_uploaded event — for now use client-side hash
				const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
				mediaHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
			}

			await invoke('create_post', {
				content: content.trim(),
				mediaHash,
				mediaType,
				mediaSize,
				visibility,
				replyTo: null,
			});

			content = '';
			mediaFile = null;
			onpost();
		} catch (e) {
			addToast(`Failed to post: ${e}`, 'error');
		}
		posting = false;
	}
</script>

<div class="border-b border-surface-light/20 p-4 bg-surface/30">
	<textarea
		bind:value={content}
		placeholder="What's on your mind?"
		maxlength="4096"
		rows="3"
		class="w-full rounded-xl bg-background px-4 py-3 text-sm text-text placeholder-text-muted/40 outline-none ring-1 ring-surface-light/30 focus:ring-primary/50 resize-none"
	></textarea>

	{#if mediaFile}
		<div class="mt-2 flex items-center gap-2 rounded-lg bg-surface-light/20 px-3 py-1.5 text-xs text-text-muted">
			<span>{mediaFile.type.startsWith('image/') ? '🖼️' : '🎬'}</span>
			<span class="truncate flex-1">{mediaFile.name}</span>
			<span class="text-text-muted/50">({(mediaFile.size / 1024).toFixed(0)} KB)</span>
			<button onclick={() => mediaFile = null} class="text-danger hover:text-danger/80">✕</button>
		</div>
	{/if}
	{#if mediaError}
		<div class="mt-1 text-xs text-danger">{mediaError}</div>
	{/if}

	<div class="mt-2 flex items-center justify-between">
		<div class="flex items-center gap-2">
			<!-- Media attach -->
			<label class="cursor-pointer rounded-lg p-1.5 text-text-muted hover:text-text hover:bg-surface-light/30 transition" title="Attach image or video (15s max)">
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" /></svg>
				<input type="file" accept="image/*,video/*" class="hidden" onchange={handleFileSelect} />
			</label>

			<!-- Visibility picker -->
			<div class="flex rounded-lg border border-surface-light/30 overflow-hidden">
				{#each [['friends', '👥'], ['public', '🌐'], ['private', '🔒']] as [v, icon]}
					<button onclick={() => visibility = v as typeof visibility}
						class="px-2 py-1 text-[10px] transition {visibility === v ? 'bg-primary/15 text-primary font-medium' : 'text-text-muted hover:bg-surface-light/20'}">
						{icon}
					</button>
				{/each}
			</div>
			<span class="text-[10px] text-text-muted/40">
				{visibility === 'public' ? 'Anyone can see' : visibility === 'friends' ? 'Friends only' : 'Only you'}
			</span>
		</div>

		<button onclick={post} disabled={(!content.trim() && !mediaFile) || posting}
			class="rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-white hover:bg-primary/90 transition disabled:opacity-50">
			{posting ? 'Posting…' : 'Post'}
		</button>
	</div>
</div>
