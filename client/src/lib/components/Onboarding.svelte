<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher } from 'svelte';

	const dispatch = createEventDispatcher();

	let step = $state<'age' | 'welcome' | 'create' | 'import' | 'backup' | 'username'>('age');
	let password = $state('');
	let confirmPassword = $state('');
	let mnemonic = $state('');
	let importedMnemonic = $state('');
	let isLoading = $state(false);
	let error = $state<string | null>(null);
	let copiedMnemonic = $state(false);

	// Username
	let username = $state('');
	let usernameError = $state<string | null>(null);

	// Age verification
	let birthYear = $state('');
	let birthMonth = $state('');
	let ageError = $state<string | null>(null);

	function verifyAge() {
		const year = parseInt(birthYear);
		const month = parseInt(birthMonth);
		if (!year || !month || year < 1900 || year > new Date().getFullYear() || month < 1 || month > 12) {
			ageError = 'Please enter a valid birth year and month.';
			return;
		}

		const now = new Date();
		const birthDate = new Date(year, month - 1);
		const age = (now.getTime() - birthDate.getTime()) / (365.25 * 24 * 60 * 60 * 1000);

		if (age < 13) {
			ageError = 'You must be at least 13 years old to use Bonchi.';
			return;
		}

		ageError = null;
		step = 'welcome';
	}

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
			await invoke('import_mnemonic', { mnemonic: importedMnemonic.trim(), password });
			dispatch('complete');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	function goToUsername() {
		step = 'username';
	}

	async function setUsername() {
		const trimmed = username.trim();
		if (trimmed.length < 3) {
			usernameError = 'Username must be at least 3 characters';
			return;
		}
		if (trimmed.length > 24) {
			usernameError = 'Username must be 24 characters or less';
			return;
		}
		if (!/^[a-zA-Z]/.test(trimmed)) {
			usernameError = 'Must start with a letter';
			return;
		}
		if (!/^[a-zA-Z0-9_]+$/.test(trimmed)) {
			usernameError = 'Only letters, numbers, and underscores';
			return;
		}

		isLoading = true;
		usernameError = null;
		try {
			await invoke('set_username', { username: trimmed });
			dispatch('complete');
		} catch (e) {
			usernameError = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	function skipUsername() {
		dispatch('complete');
	}
</script>

<div class="flex h-full items-center justify-center p-8">
	<div class="w-full max-w-md rounded-2xl bg-surface p-8 shadow-2xl border border-surface-light/30">

		<!-- Age Verification -->
		{#if step === 'age'}
			<div class="text-center">
				<div class="mb-6">
					<div class="mb-1 text-3xl font-bold text-primary">Bonchi</div>
					<div class="text-xs text-text-muted/50 mb-2">Built on Mobium</div>
					<div class="text-sm text-text-muted">Before we begin</div>
				</div>

				<p class="mb-6 text-sm text-text-muted">
					Bonchi requires users to be at least 13 years old.<br>
					Please confirm your age to continue.
				</p>

				{#if ageError}
					<div class="mb-4 rounded-lg bg-danger/15 border border-danger/30 p-3 text-sm text-danger">
						{ageError}
					</div>
				{/if}

				<div class="flex gap-3 mb-6">
					<div class="flex-1">
						<label class="mb-1 block text-xs text-text-muted text-left">Birth Month</label>
						<select
							bind:value={birthMonth}
							class="w-full rounded-lg bg-background px-3 py-2.5 text-sm text-text outline-none ring-1 ring-surface-light focus:ring-primary appearance-none"
						>
							<option value="">Month</option>
							{#each Array.from({length: 12}, (_, i) => i + 1) as m}
								<option value={String(m)}>{new Date(2000, m - 1).toLocaleString('default', { month: 'long' })}</option>
							{/each}
						</select>
					</div>
					<div class="flex-1">
						<label class="mb-1 block text-xs text-text-muted text-left">Birth Year</label>
						<input
							type="number"
							bind:value={birthYear}
							placeholder="e.g. 2005"
							min="1900"
							max={new Date().getFullYear()}
							class="w-full rounded-lg bg-background px-3 py-2.5 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"
						/>
					</div>
				</div>

				<button
					onclick={verifyAge}
					class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark"
				>
					Continue
				</button>

				<p class="mt-4 text-xs text-text-muted/60">
					Your birth date is not stored or transmitted.<br>
					This check happens entirely on your device.
				</p>
			</div>

		<!-- Welcome -->
		{:else if step === 'welcome'}
			<div class="text-center">
				<div class="mb-6">
					<div class="mb-1 text-3xl font-bold text-primary">Bonchi</div>
					<div class="text-xs text-text-muted/50 mb-2">Built on Mobium</div>
					<div class="text-sm text-text-muted">Zero-knowledge encrypted messaging</div>
				</div>

				<p class="mb-8 text-sm text-text-muted leading-relaxed">
					Your messages are end-to-end encrypted.<br>
					Not even the server can read them.
				</p>

				<div class="space-y-3">
					<button
						onclick={() => step = 'create'}
						class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark flex items-center justify-center gap-2"
					>
						<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
						</svg>
						Create New Identity
					</button>
					<button
						onclick={() => step = 'import'}
						class="w-full rounded-xl bg-surface-light px-6 py-3 font-semibold text-text transition hover:bg-surface-light/80 flex items-center justify-center gap-2"
					>
						<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
							<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
						</svg>
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

		<!-- Create -->
		{:else if step === 'create'}
			<div>
				<button onclick={() => step = 'welcome'} class="mb-4 text-sm text-text-muted hover:text-text flex items-center gap-1">
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" /></svg>
					Back
				</button>

				<h2 class="mb-6 text-xl font-bold text-text">Create Identity</h2>

				{#if error}
					<div class="mb-4 rounded-lg bg-danger/15 border border-danger/30 p-3 text-sm text-danger">{error}</div>
				{/if}

				<div class="space-y-4">
					<div>
						<label class="mb-1 block text-xs text-text-muted">Password</label>
						<input type="password" bind:value={password} placeholder="Min 12 characters"
							class="w-full rounded-lg bg-background px-4 py-2.5 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary" />
					</div>
					<div>
						<label class="mb-1 block text-xs text-text-muted">Confirm Password</label>
						<input type="password" bind:value={confirmPassword} placeholder="Confirm password"
							class="w-full rounded-lg bg-background px-4 py-2.5 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary" />
					</div>
					<button onclick={createIdentity} disabled={isLoading}
						class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50">
						{isLoading ? 'Creating...' : 'Create Identity'}
					</button>
				</div>
			</div>

		<!-- Import -->
		{:else if step === 'import'}
			<div>
				<button onclick={() => step = 'welcome'} class="mb-4 text-sm text-text-muted hover:text-text flex items-center gap-1">
					<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" /></svg>
					Back
				</button>

				<h2 class="mb-6 text-xl font-bold text-text">Restore Identity</h2>

				{#if error}
					<div class="mb-4 rounded-lg bg-danger/15 border border-danger/30 p-3 text-sm text-danger">{error}</div>
				{/if}

				<div class="space-y-4">
					<div>
						<label class="mb-1 block text-xs text-text-muted">Recovery Phrase</label>
						<textarea bind:value={importedMnemonic} placeholder="24-word recovery phrase" rows="3"
							class="w-full resize-none rounded-lg bg-background px-4 py-2.5 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary"></textarea>
					</div>
					<div>
						<label class="mb-1 block text-xs text-text-muted">Password</label>
						<input type="password" bind:value={password} placeholder="Min 12 characters"
							class="w-full rounded-lg bg-background px-4 py-2.5 text-sm text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary" />
					</div>
					<button onclick={importIdentity} disabled={isLoading}
						class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50">
						{isLoading ? 'Restoring...' : 'Restore Identity'}
					</button>
				</div>
			</div>

		<!-- Backup -->
		{:else if step === 'backup'}
			<div>
				<h2 class="mb-4 text-xl font-bold text-text">Save Your Recovery Phrase</h2>

				<div class="mb-5 rounded-lg bg-warning/10 border border-warning/30 p-3">
					<div class="mb-1 font-semibold text-warning text-sm">⚠️ Write these down</div>
					<p class="text-xs text-text-muted">This is the only way to recover your account. Never share it.</p>
				</div>

				<div class="mb-5 rounded-lg bg-surface-light p-4">
					<div class="grid grid-cols-3 gap-2">
						{#each mnemonic.split(' ') as word, i}
							<div class="flex items-center gap-1.5">
								<span class="text-xs text-text-muted w-4 text-right">{i + 1}</span>
								<span class="font-mono text-sm text-text">{word}</span>
							</div>
						{/each}
					</div>
				</div>

				<div class="space-y-2">
					<button onclick={goToUsername}
						class="w-full rounded-xl bg-accent px-6 py-3 font-semibold text-white transition hover:bg-accent-dark">
						I've Saved It — Continue
					</button>
					<button onclick={() => { navigator.clipboard.writeText(mnemonic); copiedMnemonic = true; setTimeout(() => copiedMnemonic = false, 2000); }}
						class="w-full rounded-xl bg-surface-light px-6 py-2.5 text-sm text-text-muted transition hover:text-text">
						{copiedMnemonic ? '✓ Copied' : 'Copy to Clipboard'}
					</button>
				</div>
			</div>

		{:else if step === 'username'}
			<div class="w-full max-w-md space-y-6 text-center">
				<div>
					<div class="mb-2 text-4xl">👤</div>
					<h2 class="text-2xl font-bold text-text">Choose a Username</h2>
					<p class="mt-2 text-sm text-text-muted">This is how other people will find and add you. You can change it later.</p>
				</div>

				<div class="space-y-3 text-left">
					<div>
						<label for="username" class="mb-1 block text-xs font-medium text-text-muted">Username</label>
						<input
							id="username"
							type="text"
							placeholder="e.g. alice_42"
							bind:value={username}
							onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') setUsername(); }}
							class="w-full rounded-xl border border-surface-light bg-surface px-4 py-3 text-text placeholder:text-text-muted/40 focus:border-primary focus:outline-none"
							maxlength="24"
						/>
					</div>
					<div class="text-xs text-text-muted/60">
						3-24 characters · Letters, numbers, underscores · Must start with a letter
					</div>
					{#if usernameError}
						<div class="text-xs text-danger">{usernameError}</div>
					{/if}
				</div>

				<div class="space-y-2">
					<button onclick={setUsername}
						disabled={isLoading || username.trim().length < 3}
						class="w-full rounded-xl bg-primary px-6 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-40 disabled:cursor-not-allowed">
						{isLoading ? 'Setting…' : 'Set Username'}
					</button>
					<button onclick={skipUsername}
						class="w-full rounded-xl bg-surface-light px-6 py-2.5 text-sm text-text-muted transition hover:text-text">
						Skip for now
					</button>
				</div>
			</div>
		{/if}
	</div>
</div>
