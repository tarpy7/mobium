<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { channelInfoStore, addToast } from '$lib/stores';
	import type { ChannelInfo } from '$lib/stores';

	let {
		channelId,
		channelName,
		isOwner = false,
		onclose,
	}: {
		channelId: string;
		channelName: string;
		isOwner: boolean;
		onclose: () => void;
	} = $props();

	let info = $derived($channelInfoStore.get(channelId));
	let description = $state('');
	let rules = $state('');
	let topic = $state('');
	let saving = $state(false);
	let loaded = $state(false);

	// Load channel info on mount
	$effect(() => {
		if (channelId && !loaded) {
			invoke('get_channel_info', { channelId }).catch(() => {});
		}
	});

	// Sync local state when info arrives from server
	$effect(() => {
		if (info && !loaded) {
			description = info.description;
			rules = info.rules;
			topic = info.topic;
			loaded = true;
		}
	});

	async function save() {
		if (saving) return;
		saving = true;
		try {
			await invoke('update_channel_info', {
				channelId,
				description: description.trim(),
				rules: rules.trim(),
				topic: topic.trim(),
			});
			onclose();
		} catch (e) {
			addToast(`Failed: ${e}`, 'error');
		}
		saving = false;
	}
</script>

<!-- Backdrop -->
<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onclick={onclose}>
	<!-- Modal -->
	<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
	<div class="relative w-full max-w-lg rounded-2xl border border-surface-light/30 bg-surface shadow-2xl" onclick={(e: MouseEvent) => e.stopPropagation()}>
		<!-- Header -->
		<div class="flex items-center justify-between border-b border-surface-light/20 px-6 py-4">
			<div>
				<h2 class="text-base font-bold text-text">Channel Settings</h2>
				<p class="text-xs text-text-muted mt-0.5">{channelName}</p>
			</div>
			<button onclick={onclose} class="rounded-lg p-1 text-text-muted hover:text-text hover:bg-surface-light/40 transition">
				<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>

		<!-- Body -->
		<div class="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
			<!-- Topic -->
			<div>
				<label class="text-[10px] font-bold uppercase tracking-wider text-text-muted/60 mb-1.5 block">Topic</label>
				{#if isOwner}
					<input type="text" bind:value={topic} placeholder="What's this channel about right now?"
						maxlength="256"
						class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text outline-none ring-1 ring-surface-light/50 focus:ring-primary transition" />
				{:else}
					<p class="text-sm text-text {!topic ? 'text-text-muted/40 italic' : ''}">{topic || 'No topic set'}</p>
				{/if}
			</div>

			<!-- Description -->
			<div>
				<label class="text-[10px] font-bold uppercase tracking-wider text-text-muted/60 mb-1.5 block">Description</label>
				{#if isOwner}
					<textarea bind:value={description} placeholder="Describe this channel…"
						maxlength="1024" rows="3"
						class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text outline-none ring-1 ring-surface-light/50 focus:ring-primary transition resize-none"></textarea>
				{:else}
					<p class="text-sm text-text whitespace-pre-wrap {!description ? 'text-text-muted/40 italic' : ''}">{description || 'No description'}</p>
				{/if}
			</div>

			<!-- Rules -->
			<div>
				<label class="text-[10px] font-bold uppercase tracking-wider text-text-muted/60 mb-1.5 block">Rules</label>
				{#if isOwner}
					<textarea bind:value={rules} placeholder="Channel rules (visible to all members)…"
						maxlength="2048" rows="4"
						class="w-full rounded-lg bg-background px-3 py-2 text-sm text-text outline-none ring-1 ring-surface-light/50 focus:ring-primary transition resize-none"></textarea>
					<p class="text-[10px] text-text-muted/40 mt-1">Supports plain text. Keep it concise.</p>
				{:else}
					<p class="text-sm text-text whitespace-pre-wrap {!rules ? 'text-text-muted/40 italic' : ''}">{rules || 'No rules set'}</p>
				{/if}
			</div>

			<!-- Channel info (read-only) -->
			<div class="pt-2 border-t border-surface-light/20 space-y-2">
				<div>
					<label class="text-[10px] font-bold uppercase tracking-wider text-text-muted/60 mb-0.5 block">Access</label>
					<span class="text-xs text-text-muted">{info?.accessMode === 'private' ? '🔒 Private (invite only)' : '🌐 Public'}</span>
				</div>
				<div>
					<label class="text-[10px] font-bold uppercase tracking-wider text-text-muted/60 mb-0.5 block">Channel ID</label>
					<button onclick={() => { navigator.clipboard.writeText(channelId); addToast('Copied', 'success'); }}
						class="text-[10px] text-text-muted/50 font-mono hover:text-primary transition break-all text-left">
						{channelId}
					</button>
				</div>
			</div>
		</div>

		<!-- Footer (owner only) -->
		{#if isOwner}
			<div class="flex items-center justify-end gap-2 border-t border-surface-light/20 px-6 py-3">
				<button onclick={onclose}
					class="rounded-lg px-4 py-1.5 text-xs text-text-muted hover:text-text transition">Cancel</button>
				<button onclick={save} disabled={saving}
					class="rounded-lg bg-primary px-4 py-1.5 text-xs font-medium text-white hover:bg-primary/90 transition disabled:opacity-50">
					{saving ? 'Saving…' : 'Save Changes'}
				</button>
			</div>
		{/if}
	</div>
</div>
