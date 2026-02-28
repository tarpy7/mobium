<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';
	import { createEventDispatcher, onMount } from 'svelte';

	const dispatch = createEventDispatcher();

	let profiles = $state<string[]>([]);
	let isLoading = $state(true);
	let error = $state<string | null>(null);
	let showCreate = $state(false);
	let newProfileName = $state('');
	let isCreating = $state(false);

	onMount(async () => {
		await loadProfiles();
	});

	async function loadProfiles() {
		isLoading = true;
		error = null;
		try {
			profiles = await invoke<string[]>('list_profiles');
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isLoading = false;
		}
	}

	async function selectProfile(name: string) {
		error = null;
		try {
			await invoke('select_profile', { profileName: name });
			dispatch('selected', { profile: name });
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		}
	}

	async function createProfile() {
		if (!newProfileName.trim()) {
			error = 'Please enter a profile name';
			return;
		}

		isCreating = true;
		error = null;
		try {
			await invoke('create_profile', { profileName: newProfileName.trim() });
			dispatch('selected', { profile: newProfileName.trim() });
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			isCreating = false;
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			createProfile();
		}
	}
</script>

<div class="flex h-full items-center justify-center bg-background p-8">
	<div class="w-full max-w-md rounded-xl bg-surface p-8 shadow-2xl">
		<div class="text-center mb-8">
			<div class="mb-2 text-4xl font-bold text-primary">Discable</div>
			<div class="text-text-muted">Choose a profile</div>
		</div>

		{#if error}
			<div class="mb-4 rounded-lg bg-danger/20 p-3 text-danger text-sm">
				{error}
			</div>
		{/if}

		{#if isLoading}
			<div class="text-center text-text-muted animate-pulse">Loading profiles...</div>
		{:else if showCreate}
			<div class="space-y-4">
				<div>
					<label class="mb-2 block text-sm text-text-muted" for="profile-name">Profile Name</label>
					<input
						id="profile-name"
						type="text"
						bind:value={newProfileName}
						onkeydown={handleKeydown}
						placeholder="e.g. Alice, Work, Testing"
						disabled={isCreating}
						class="w-full rounded-lg bg-background px-4 py-3 text-text placeholder-text-muted/50 outline-none ring-1 ring-surface-light focus:ring-primary disabled:opacity-50"
					/>
				</div>
				<div class="flex gap-2">
					<button
						onclick={createProfile}
						disabled={isCreating || !newProfileName.trim()}
						class="flex-1 rounded-lg bg-primary px-4 py-3 font-semibold text-white transition hover:bg-primary-dark disabled:opacity-50"
					>
						{#if isCreating}
							Creating...
						{:else}
							Create Profile
						{/if}
					</button>
					<button
						onclick={() => { showCreate = false; newProfileName = ''; }}
						disabled={isCreating}
						class="rounded-lg bg-surface-light px-4 py-3 text-text-muted transition hover:text-text disabled:opacity-50"
					>
						Back
					</button>
				</div>
			</div>
		{:else}
			<div class="space-y-2">
				{#each profiles as profile}
					<button
						onclick={() => selectProfile(profile)}
						class="w-full rounded-lg bg-background px-4 py-3 text-left text-text transition hover:bg-surface-light hover:ring-1 hover:ring-primary/50"
					>
						<span class="font-medium">{profile}</span>
					</button>
				{/each}

				{#if profiles.length === 0}
					<div class="text-center text-text-muted text-sm py-4">
						No profiles yet. Create one to get started.
					</div>
				{/if}
			</div>

			<button
				onclick={() => { showCreate = true; }}
				class="mt-4 w-full rounded-lg border border-dashed border-surface-light px-4 py-3 text-text-muted transition hover:border-primary hover:text-primary"
			>
				+ New Profile
			</button>
		{/if}

		<div class="mt-6 text-center">
			<p class="text-xs text-text-muted">
				Each profile has its own identity, keys, and message history.
			</p>
		</div>
	</div>
</div>
