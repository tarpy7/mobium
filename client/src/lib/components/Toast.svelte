<script lang="ts">
	import { toastStore, dismissToast, activeConversationStore } from '$lib/stores';

	function handleClick(conversationId: string, toastId: string) {
		activeConversationStore.set(conversationId);
		dismissToast(toastId);
	}
</script>

{#if $toastStore.length > 0}
	<div class="fixed top-4 right-4 z-50 flex flex-col gap-2 pointer-events-none" style="max-width: 360px;">
		{#each $toastStore as toast (toast.id)}
			<div
				role="button"
				tabindex="0"
				onclick={() => handleClick(toast.conversationId, toast.id)}
				onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && handleClick(toast.conversationId, toast.id)}
				class="pointer-events-auto flex items-start gap-3 rounded-lg border border-surface-light bg-surface p-3 shadow-lg cursor-pointer transition hover:bg-surface-light animate-slide-in"
			>
				<!-- DM icon -->
				<div class="flex h-9 w-9 items-center justify-center rounded-full bg-primary/20 flex-shrink-0 mt-0.5">
					<svg class="h-4 w-4 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
					</svg>
				</div>
				<div class="min-w-0 flex-1">
					<div class="text-sm font-semibold text-text truncate">{toast.title}</div>
					<div class="mt-0.5 text-xs text-text-muted truncate">{toast.body}</div>
					<div class="mt-1 text-[10px] text-primary">Click to open conversation</div>
				</div>
				<button
					onclick={(e: MouseEvent) => { e.stopPropagation(); dismissToast(toast.id); }}
					class="flex-shrink-0 rounded p-0.5 text-text-muted hover:text-text transition"
					title="Dismiss"
				>
					<svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
					</svg>
				</button>
			</div>
		{/each}
	</div>
{/if}

<style>
	@keyframes slide-in {
		from {
			opacity: 0;
			transform: translateX(100%);
		}
		to {
			opacity: 1;
			transform: translateX(0);
		}
	}
	:global(.animate-slide-in) {
		animation: slide-in 0.25s ease-out;
	}
</style>
