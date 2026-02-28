<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';
	import { connectionStore } from '$lib/stores';
	import { cancelReconnect } from '$lib/events';

	const dispatch = createEventDispatcher();

	let serverUrl = $state('');
	let isLoading = $state(false);
	let error = $state<string | null>(null);

	async function connect() {
		if (!serverUrl.trim()) {
			error = 'Please enter a server URL';
			return;
		}

		isLoading = true;
		error = null;
		cancelReconnect();

		try {
			const connected = await invoke<boolean>('connect_server', { serverUrl: serverUrl.trim() });
			
			if (connected) {
				connectionStore.update(s => ({
					...s,
					connected: true,
					serverUrl: serverUrl.trim(),
					reconnecting: false,
					error: null
				}));
				dispatch('close');
			} else {
				error = 'Failed to connect';
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Connection error';
		} finally {
			isLoading = false;
		}
	}

	async function disconnect() {
		cancelReconnect();
		try {
			await invoke('disconnect_server');
			connectionStore.update(s => ({
				...s,
				connected: false,
				reconnecting: false,
				serverUrl: null,
				error: null
			}));
		} catch (e) {
			console.error('Failed to disconnect:', e);
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			connect();
		}
	}
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
	<div class="w-full max-w-md rounded-xl bg-surface p-6 shadow-2xl">
		<div class="mb-6 flex items-center justify-between">
			<h2 class="text-xl font-bold text-text">
				{$connectionStore.connected ? 'Connection' : 'Connect to Server'}
			</h2>
			<button
				onclick={() => dispatch('close')}
				class="text-text-muted hover:text-text"
				title="Close"
			>
				<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>

		{#if $connectionStore.connected}
			<div class="mb-6 rounded-lg bg-success/10 p-4">
				<div class="flex items-center gap-2 text-success">
					<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
					</svg>
					<span class="font-semibold">Connected</span>
				</div>
				<div class="mt-2 text-sm text-text-muted">
					{$connectionStore.serverUrl}
				</div>
			</div>

			<button
				onclick={disconnect}
				class="w-full rounded-lg bg-danger px-6 py-3 font-semibold text-white transition hover:opacity-90"
			>
				Disconnect
			</button>
		{:else}
			{#if error}
				<div class="mb-4 rounded-lg bg-danger/20 p-3 text-sm text-danger">
					{error}
				</div>
			{/if}

			{#if $connectionStore.reconnecting}
				<div class="mb-4 rounded-lg bg-warning/10 p-3">
					<div class="flex items-center gap-2 text-warning text-sm">
						<span class="animate-spin">&#9696;</span>
						<span>{$connectionStore.error || 'Reconnecting...'}</span>
					</div>
					<button
						onclick={cancelReconnect}
						class="mt-2 text-xs text-text-muted hover:text-text"
					>
						Cancel auto-reconnect
					</button>
				</div>
			{/if}

			<div class="mb-6">
				<label class="mb-2 block text-sm text-text-muted" for="server-url">Server URL</label>
				<input
					id="server-url"
					type="text"
					bind:value={serverUrl}
					onkeydown={handleKeydown}
					placeholder="localhost:8443 or https://example.com"
					class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
				/>
				<p class="mt-2 text-xs text-text-muted">
					Examples: localhost:8443, 192.168.1.100:8443, or your-domain.com
				</p>
			</div>

			<div class="space-y-3">
				<button
					onclick={connect}
					disabled={isLoading}
					class="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50"
				>
					{#if isLoading}
						Connecting...
					{:else}
						Connect
					{/if}
				</button>

				<button
					onclick={() => dispatch('close')}
					class="w-full rounded-lg bg-surface-light px-6 py-3 text-text transition hover:bg-secondary"
				>
					Cancel
				</button>
			</div>
		{/if}
	</div>
</div>
