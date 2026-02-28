<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	let step = $state<'welcome' | 'create' | 'import' | 'backup'>('welcome');
	let password = $state('');
	let confirmPassword = $state('');
	let mnemonic = $state('');
	let importedMnemonic = $state('');
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let copiedMnemonic = $state(false);

	async function createIdentity() {
		if (password.length < 12) {
			error = 'Password must be at least 12 characters';
			return;
		}
		if (password !== confirmPassword) {
			error = 'Passwords do not match';
			return;
		}

		isLoading = true;
		error = null;

		try {
			// Backend returns Result<String, String> - on success, returns the mnemonic directly
			const result = await invoke<string>('generate_identity', { password });
			mnemonic = result;
			step = 'backup';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	async function importIdentity() {
		if (!importedMnemonic.trim()) {
			error = 'Please enter your recovery phrase';
			return;
		}
		if (password.length < 12) {
			error = 'Password must be at least 12 characters';
			return;
		}

		isLoading = true;
		error = null;

		try {
			// Backend returns Result<(), String> - on success, returns null
			await invoke('import_mnemonic', { 
				mnemonic: importedMnemonic.trim(),
				password 
			});
			dispatch('complete');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	function completeOnboarding() {
		dispatch('complete');
	}
</script>

<div class="flex h-full items-center justify-center bg-background p-8">
	<div class="w-full max-w-md rounded-xl bg-surface p-8 shadow-2xl">
		{#if step === 'welcome'}
			<div class="text-center">
				<div class="mb-6">
					<div class="mb-2 text-4xl font-bold text-primary">Mobium</div>
					<div class="text-text-muted">Zero-knowledge encrypted messaging</div>
				</div>
				
				<p class="mb-8 text-text-muted">
					Welcome to Mobium. Your messages are end-to-end encrypted and 
					can only be read by you and your contacts.
				</p>

				<div class="space-y-3">
					<button
						onclick={() => step = 'create'}
						class="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark"
					>
						Create New Identity
					</button>
					<button
						onclick={() => step = 'import'}
						class="w-full rounded-lg bg-surface-light px-6 py-3 font-semibold text-text transition hover:bg-secondary"
					>
						Restore from Backup
					</button>
				</div>

				<button
					onclick={() => dispatch('switchProfile')}
					class="mt-4 w-full text-xs text-text-muted hover:text-primary transition"
				>
					Switch Profile
				</button>
			</div>

		{:else if step === 'create'}
			<div>
				<button
					onclick={() => step = 'welcome'}
					class="mb-4 text-text-muted hover:text-text"
				>
					← Back
				</button>

				<h2 class="mb-6 text-2xl font-bold text-text">Create Identity</h2>

				{#if error}
					<div class="mb-4 rounded-lg bg-danger/20 p-3 text-danger">
						{error}
					</div>
				{/if}

				<div class="space-y-4">
					<div>
						<label class="mb-2 block text-sm text-text-muted">Password</label>
						<input
							type="password"
							bind:value={password}
							placeholder="Enter a strong password (min 12 chars)"
							class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
						/>
					</div>

					<div>
						<label class="mb-2 block text-sm text-text-muted">Confirm Password</label>
						<input
							type="password"
							bind:value={confirmPassword}
							placeholder="Confirm your password"
							class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
						/>
					</div>

					<button
						onclick={createIdentity}
						disabled={isLoading}
						class="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50"
					>
						{#if isLoading}
							Creating...
						{:else}
							Create Identity
						{/if}
					</button>
				</div>
			</div>

		{:else if step === 'import'}
			<div>
				<button
					onclick={() => step = 'welcome'}
					class="mb-4 text-text-muted hover:text-text"
				>
					← Back
				</button>

				<h2 class="mb-6 text-2xl font-bold text-text">Restore Identity</h2>

				{#if error}
					<div class="mb-4 rounded-lg bg-danger/20 p-3 text-danger">
						{error}
					</div>
				{/if}

				<div class="space-y-4">
					<div>
						<label class="mb-2 block text-sm text-text-muted">Recovery Phrase</label>
						<textarea
							bind:value={importedMnemonic}
							placeholder="Enter your 24-word recovery phrase"
							rows="3"
							class="w-full resize-none rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
						></textarea>
					</div>

					<div>
						<label class="mb-2 block text-sm text-text-muted">Password</label>
						<input
							type="password"
							bind:value={password}
							placeholder="Enter a strong password (min 12 chars)"
							class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
						/>
					</div>

					<button
						onclick={importIdentity}
						disabled={isLoading}
						class="w-full rounded-lg bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50"
					>
						{#if isLoading}
							Restoring...
						{:else}
							Restore Identity
						{/if}
					</button>
				</div>
			</div>

		{:else if step === 'backup'}
			<div>
				<h2 class="mb-4 text-2xl font-bold text-text">Backup Your Recovery Phrase</h2>

				<div class="mb-6 rounded-lg bg-warning/10 p-4">
					<div class="mb-2 font-semibold text-warning">⚠️ Important</div>
					<p class="text-sm text-text-muted">
						Write down these 24 words in order. This is the ONLY way to recover 
						your account. Never share it with anyone.
					</p>
				</div>

				<div class="mb-6 rounded-lg bg-surface-light p-6">
					<div class="grid grid-cols-3 gap-3">
						{#each mnemonic.split(' ') as word, i}
							<div class="flex items-center gap-2">
								<span class="text-xs text-text-muted">{i + 1}</span>
								<span class="font-mono text-text">{word}</span>
							</div>
						{/each}
					</div>
				</div>

				<div class="space-y-3">
					<button
						onclick={completeOnboarding}
						class="w-full rounded-lg bg-success px-6 py-3 font-semibold text-white transition hover:opacity-90"
					>
						I've Written It Down - Continue
					</button>
					
					<button
						onclick={() => { navigator.clipboard.writeText(mnemonic); copiedMnemonic = true; setTimeout(() => copiedMnemonic = false, 2000); }}
						class="w-full rounded-lg bg-surface-light px-6 py-3 text-sm text-text-muted transition hover:text-text"
					>
						{copiedMnemonic ? 'Copied!' : 'Copy to Clipboard'}
					</button>
				</div>
			</div>
		{/if}
	</div>
</div>