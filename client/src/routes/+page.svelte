<script lang="ts">
	import { onMount } from 'svelte';
	import { invoke } from '@tauri-apps/api/core';
	import ProfilePicker from '$lib/components/ProfilePicker.svelte';
	import Onboarding from '$lib/components/Onboarding.svelte';
	import Login from '$lib/components/Login.svelte';
	import MainApp from '$lib/components/MainApp.svelte';
	import { setupEventListeners } from '$lib/events';
	import { get } from 'svelte/store';
	import { identityStore, nicknamesStore, connectionStore, conversationsStore, upsertConversation } from '$lib/stores';

	let profileSelected = $state(false);
	let hasIdentity = $state<boolean | null>(null);
	let isUnlocked = $state(false);
	let isLoading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		// Setup Tauri event listeners (fire-and-forget, don't block startup)
		setupEventListeners().catch(e => console.warn('Event listener setup failed:', e));

		// Check if there are any profiles — if only one exists, auto-select it
		try {
			const profiles = await invoke<string[]>('list_profiles');
			if (profiles.length === 1) {
				// Only one profile — auto-select it and skip the picker
				await invoke('select_profile', { profileName: profiles[0] });
				profileSelected = true;
				await checkIdentity();
			} else if (profiles.length === 0) {
				// No profiles yet — show the picker so user can create one
				isLoading = false;
			} else {
				// Multiple profiles — show the picker
				isLoading = false;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load profiles';
			isLoading = false;
		}
	});

	async function checkIdentity() {
		try {
			hasIdentity = await invoke<boolean>('has_identity');
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to check identity';
			hasIdentity = false;
		} finally {
			isLoading = false;
		}
	}

	async function onProfileSelected(event: CustomEvent<{ profile: string }>) {
		profileSelected = true;
		isLoading = true;
		await checkIdentity();
	}

	async function loadPostUnlock() {
		// Load pubkey
		try {
			const pubkey = await invoke<string>('get_pubkey');
			identityStore.set({ pubkey, mnemonicBackedUp: false });
		} catch (e) {
			console.warn('Failed to load pubkey:', e);
		}

		// Load nicknames from DB
		try {
			const nicks = await invoke<[string, string][]>('get_nicknames');
			const map = new Map<string, string>();
			for (const [pk, nick] of nicks) {
				map.set(pk, nick);
			}
			nicknamesStore.set(map);
		} catch (e) {
			console.warn('Failed to load nicknames:', e);
		}

		// Load saved conversations from DB
		try {
			const dbConvos = await invoke<{
				id: string;
				name: string;
				conversation_type: string;
				last_message_at: number | null;
			}[]>('get_conversations');
			for (const conv of dbConvos) {
				upsertConversation({
					id: conv.id,
					name: conv.name,
					type: conv.conversation_type === 'group' ? 'group' : 'dm',
					unreadCount: 0,
				});
			}
		} catch (e) {
			console.warn('Failed to load conversations:', e);
		}

		// Auto-reconnect to last server (only if not already connected)
		try {
			const alreadyConnected = get(connectionStore).connected;
			if (!alreadyConnected) {
				const lastServer = await invoke<string | null>('get_last_server');
				if (lastServer) {
					console.log('[auto-reconnect] connecting to last server:', lastServer);
					connectionStore.update(s => ({ ...s, serverUrl: lastServer }));
					await invoke<boolean>('connect_server', { serverUrl: lastServer });
				}
			}
		} catch (e) {
			console.warn('Auto-reconnect failed (will retry):', e);
			// The connection_lost event handler will schedule reconnects
		}
	}

	function onIdentityCreated() {
		// After onboarding, identity is already decrypted in AppState
		hasIdentity = true;
		isUnlocked = true;
		loadPostUnlock();
	}

	function onIdentityUnlocked() {
		isUnlocked = true;
		loadPostUnlock();
	}

	function onIdentityReset() {
		// Identity was deleted — go back to onboarding
		hasIdentity = false;
		isUnlocked = false;
	}

	function onSwitchProfile() {
		// Go back to the profile picker
		profileSelected = false;
		hasIdentity = null;
		isUnlocked = false;
		error = null;
	}
</script>

{#if isLoading}
	<div class="flex h-full items-center justify-center">
		<div class="text-center">
			<div class="mb-2 text-3xl font-bold text-primary">Discable</div>
			<div class="animate-pulse text-text-muted">Initializing...</div>
		</div>
	</div>
{:else if error}
	<div class="flex h-full items-center justify-center">
		<div class="text-center">
			<div class="mb-2 text-danger">Error</div>
			<div class="text-text-muted">{error}</div>
		</div>
	</div>
{:else if !profileSelected}
	<ProfilePicker on:selected={onProfileSelected} />
{:else if !hasIdentity}
	<Onboarding on:complete={onIdentityCreated} on:switchProfile={onSwitchProfile} />
{:else if !isUnlocked}
	<Login on:unlocked={onIdentityUnlocked} on:reset={onIdentityReset} on:switchProfile={onSwitchProfile} />
{:else}
	<MainApp />
{/if}
