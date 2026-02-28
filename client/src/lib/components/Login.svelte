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
		if (!password) {
			error = 'Please enter your password';
			return;
		}

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
		if (event.key === 'Enter') {
			unlock();
		}
	}
</script>

<div class="flex h-full items-center justify-center bg-background p-8">
	<div class="w-full max-w-md rounded-xl bg-surface p-8 shadow-2xl">
		<div class="text-center mb-8">
			<div class="mb-2 text-4xl font-bold text-primary">Mobium</div>
			<div class="text-text-muted">Welcome back</div>
		</div>

		{#if error}
			<div class="mb-4 rounded-lg bg-danger/20 p-3 text-danger text-sm">
				{error}
			</div>
		{/if}

		{#if showResetConfirm}
			<div class="mb-4 rounded-lg bg-warning/10 p-4">
				<div class="mb-2 font-semibold text-warning">Reset Identity?</div>
				<p class="text-sm text-text-muted mb-4">
					This will permanently delete your identity and all local data.
					You will need your recovery phrase to restore your account, or
					you can create a new identity.
				</p>
				<div class="flex gap-2">
					<button
						onclick={resetIdentity}
						disabled={isResetting}
						class="flex-1 rounded-lg bg-danger px-4 py-2 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
					>
						{#if isResetting}
							Resetting...
						{:else}
							Yes, Delete Everything
						{/if}
					</button>
					<button
						onclick={() => { showResetConfirm = false; }}
						disabled={isResetting}
						class="flex-1 rounded-lg bg-surface-light px-4 py-2 text-sm text-text-muted transition hover:text-text disabled:opacity-50"
					>
						Cancel
					</button>
				</div>
			</div>
		{/if}

		<div class="space-y-4">
			<div>
				<label class="mb-2 block text-sm text-text-muted" for="unlock-password">Password</label>
				<input
					id="unlock-password"
					type="password"
					bind:value={password}
					onkeydown={handleKeydown}
					placeholder="Enter your password to unlock"
					disabled={isLoading}
					class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary disabled:opacity-50"
				/>
			</div>

			<button
				onclick={unlock}
				disabled={isLoading || !password}
				class="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50"
			>
				{#if isLoading}
					Unlocking...
				{:else}
					Unlock
				{/if}
			</button>
		</div>

		<div class="mt-6 text-center space-y-2">
			<p class="text-xs text-text-muted">
				Your identity is encrypted and stored locally.
				Enter your password to decrypt it.
			</p>
			<div class="flex justify-center gap-4">
				{#if !showResetConfirm}
					<button
						onclick={() => { showResetConfirm = true; }}
						class="text-xs text-text-muted hover:text-danger transition"
					>
						Forgot password? Reset identity
					</button>
				{/if}
				<button
					onclick={() => dispatch('switchProfile')}
					class="text-xs text-text-muted hover:text-primary transition"
				>
					Switch Profile
				</button>
			</div>
		</div>
	</div>
</div>
