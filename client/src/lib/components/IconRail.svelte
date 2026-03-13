<script lang="ts">
	import { conversationsStore, activeConversationStore, connectionStore, addToast } from '$lib/stores';

	let {
		activeView,
		onviewchange,
		onconnect,
	}: {
		activeView: string;
		onviewchange: (view: string) => void;
		onconnect: () => void;
	} = $props();

	let channels = $derived($conversationsStore.filter(c => c.type === 'group'));
	let totalUnread = $derived($conversationsStore.reduce((s, c) => s + c.unreadCount, 0));
	let dmUnread = $derived($conversationsStore.filter(c => c.type === 'dm' || c.type === 'group_dm').reduce((s, c) => s + c.unreadCount, 0));
</script>

<div class="flex h-full w-[52px] flex-col items-center bg-surface border-r border-surface-light/20 py-2 gap-1">
	<!-- Bonchi Logo -->
	<div class="flex h-10 w-10 items-center justify-center mb-1">
		<div class="flex h-9 w-9 items-center justify-center rounded-xl font-black text-base tracking-tight text-white" style="background: linear-gradient(135deg, #e07a5f 0%, #b8a9c9 50%, #81b29a 100%);">
			B
		</div>
	</div>

	<!-- Home / DMs -->
	<button
		onclick={() => onviewchange('home')}
		class="relative flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{activeView === 'home' ? 'bg-primary text-white rounded-xl' : 'bg-surface-light/40 text-text-muted hover:bg-primary/20 hover:text-primary hover:rounded-xl'}"
		title="Direct Messages"
	>
		<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
		</svg>
		{#if dmUnread > 0}
			<span class="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger text-[10px] font-bold text-white px-1">{dmUnread}</span>
		{/if}
	</button>

	<!-- Feed -->
	<button
		onclick={() => onviewchange('feed')}
		class="flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{activeView === 'feed' ? 'bg-primary text-white rounded-xl' : 'bg-surface-light/40 text-text-muted hover:bg-primary/20 hover:text-primary hover:rounded-xl'}"
		title="Feed"
	>
		<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z" />
		</svg>
	</button>

	<!-- Friends -->
	<button
		onclick={() => onviewchange('friends')}
		class="flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{activeView === 'friends' ? 'bg-accent text-white rounded-xl' : 'bg-surface-light/40 text-text-muted hover:bg-accent/20 hover:text-accent hover:rounded-xl'}"
		title="Friends"
	>
		<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
		</svg>
	</button>

	<!-- Divider -->
	<div class="w-6 border-t border-surface-light/30 my-1"></div>

	<!-- Channels -->
	{#each channels as channel}
		<button
			onclick={() => { activeConversationStore.set(channel.id); onviewchange('channel:' + channel.id); }}
			class="relative flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200 group
				{activeView === 'channel:' + channel.id ? 'bg-primary text-white rounded-xl' : 'bg-surface-light/40 text-text-muted hover:bg-primary/20 hover:text-primary hover:rounded-xl'}"
			title={channel.name}
		>
			<span class="text-sm font-bold">{channel.name.charAt(0).toUpperCase()}</span>
			{#if channel.unreadCount > 0}
				<span class="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger text-[10px] font-bold text-white px-1">{channel.unreadCount}</span>
			{/if}
			<!-- Active indicator -->
			{#if activeView === 'channel:' + channel.id}
				<div class="absolute left-0 top-1/2 -translate-y-1/2 -translate-x-[2px] w-1 h-5 rounded-r-full bg-primary"></div>
			{/if}
		</button>
	{/each}

	<!-- Add channel -->
	<button
		onclick={() => onviewchange('create')}
		class="flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{activeView === 'create' ? 'bg-accent text-white rounded-xl' : 'bg-surface-light/40 text-accent/60 hover:bg-accent/20 hover:text-accent hover:rounded-xl'}"
		title="Create or Join Channel"
	>
		<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
		</svg>
	</button>

	<!-- Spacer -->
	<div class="flex-1"></div>

	<!-- Connection status -->
	<button
		onclick={onconnect}
		class="flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{$connectionStore.connected ? 'bg-accent/15 text-accent hover:bg-accent/25' : 'bg-danger/15 text-danger hover:bg-danger/25'}"
		title={$connectionStore.connected ? 'Connected' : 'Disconnected — click to connect'}
	>
		<div class="relative">
			<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />
			</svg>
			<span class="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-surface {$connectionStore.connected ? 'bg-accent' : 'bg-danger'}"></span>
		</div>
	</button>

	<!-- Settings -->
	<button
		onclick={() => onviewchange('settings')}
		class="flex h-10 w-10 items-center justify-center rounded-2xl transition-all duration-200
			{activeView === 'settings' ? 'bg-surface-light text-primary rounded-xl' : 'text-text-muted hover:bg-surface-light/40 hover:text-text hover:rounded-xl'}"
		title="Settings"
	>
		<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
			<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
		</svg>
	</button>
</div>
