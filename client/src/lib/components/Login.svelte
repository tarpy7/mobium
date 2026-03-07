<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	let password = $state('');
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let showResetConfirm = $state(false);
	let isResetting = $state(false);

	async function unlock() {
		if (!password) { error = 'Please enter your password'; return; }
		isLoading = true;
		error = null;
		try {
			await invoke('unlock_identity', { password });
			dispatch('unlocked');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	async function resetIdentity() {
		isResetting = true;
		error = null;
		try {
			await invoke('reset_identity');
			dispatch('reset');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isResetting = false;
			showResetConfirm = false;
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') unlock();
	}
</script>

<div class="flex h-full items-center justify-center p-8">
	<div class="w-full max-w-sm rounded-2xl bg-surface p-8 shadow-2xl border border-surface-light/30">
		<div class="text-center mb-6">
			<div class="mb-1 text-3xl font-bold text-primary">Mobium</div>
			<div class="text-sm text-text-muted">Welcome back</div>
		</div>

		{#if error}
			<div class="mb-4 rounded-lg bg-danger/15 border border-danger/30 p-3 text-sm text-danger">{error}</div>
		{/if}

		{#if showResetConfirm}
			<div class="mb-4 rounded-lg bg-warning/10 border border-warning/30 p-3">
				<div class="mb-1 font-semibold text-warning text-sm">Reset Identity?</div>
				<p class="text-xs text-text-muted mb-3">This permanently deletes your identity and all local data.</p>
				<div class="flex gap-2">
					<button onclick={resetIdentity} disabled={isResetting}
						class="flex-1 rounded-lg bg-danger px-3 py-2 text-xs font-semibold text-white transition hover:opacity-90 disabled:opacity-50">
						{isResetting ? 'Resetting...' : 'Delete Everything'}
					</button>
					<button onclick={() => { showResetConfirm = false; }} disabled={isResetting}
						class="flex-1 rounded-lg bg-surface-light px-3 py-2 text-xs text-text-muted transition hover:text-text disabled:opacity-50">
						Cancel
					</button>
				</div>
			</div>
		{/if}

		<div class="space-y-3">
			<input
				type="password"
				bind:value={password}
				onkeydown={handleKeydown}
				placeholder="Enter password"
				disabled={isLoading}
				class="w-full rounded-xl bg-background px-4 py-3 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary disabled:opacity-50"
			/>
			<button onclick={unlock} disabled={isLoading || !password}
				class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50 flex items-center justify-center gap-2">
				<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
				</svg>
				{isLoading ? 'Unlocking...' : 'Unlock'}
			</button>
		</div>

		<div class="mt-5 text-center flex justify-center gap-4">
			{#if !showResetConfirm}
				<button onclick={() => { showResetConfirm = true; }} class="text-xs text-text-muted hover:text-danger transition">
					Reset identity
				</button>
			{/if}
			<button onclick={() => dispatch('switchProfile')} class="text-xs text-text-muted hover:text-primary transition">
				Switch profile
			</button>
		</div>
	</div>
</div>
