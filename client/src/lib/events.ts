/**
 * Tauri event listeners for WebSocket messages from the backend.
 * Call setupEventListeners() once on app mount to wire up all handlers.
 */

import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import { get } from 'svelte/store';
import {
	connectionStore,
	conversationsStore,
	addMessage,
	addToast,
	upsertConversation,
	identityStore,
	activeConversationStore,
	displayName,
	type Message
} from '$lib/stores';

let listenersSetup = false;

/** Auto-reconnect state */
let reconnectAttempt = 0;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
const MAX_RECONNECT_DELAY = 30_000; // 30 seconds

function scheduleReconnect() {
	if (reconnectTimer) return; // already scheduled

	const connState = get(connectionStore);
	if (!connState.serverUrl) return; // no server to reconnect to

	reconnectAttempt++;
	// Exponential backoff with jitter: base 1s, 2s, 4s, 8s, 16s, 30s, 30s...
	// Random jitter ±25% prevents timing correlation attacks that could
	// fingerprint users by their reconnect patterns.
	const base = Math.min(1000 * Math.pow(2, reconnectAttempt - 1), MAX_RECONNECT_DELAY);
	const jitter = base * (0.75 + Math.random() * 0.5); // ±25%
	const delay = Math.round(jitter);

	console.log(`[reconnect] attempt ${reconnectAttempt} in ${delay}ms`);
	connectionStore.update(s => ({ ...s, reconnecting: true, error: `Reconnecting in ${Math.round(delay / 1000)}s...` }));

	reconnectTimer = setTimeout(async () => {
		reconnectTimer = null;
		const state = get(connectionStore);
		if (state.connected || !state.serverUrl) return;

		console.log(`[reconnect] attempting to connect to ${state.serverUrl}`);
		try {
			await invoke<boolean>('connect_server', { serverUrl: state.serverUrl });
			// auth_success event will flip connected to true and reset reconnectAttempt
		} catch (e) {
			console.warn('[reconnect] failed:', e);
			scheduleReconnect(); // try again
		}
	}, delay);
}

export function cancelReconnect() {
	if (reconnectTimer) {
		clearTimeout(reconnectTimer);
		reconnectTimer = null;
	}
	reconnectAttempt = 0;
	connectionStore.update(s => ({ ...s, reconnecting: false }));
}

/** Request desktop notification permission once */
let notifPermissionChecked = false;
async function ensureNotifPermission() {
	if (notifPermissionChecked) return;
	notifPermissionChecked = true;
	if ('Notification' in window && Notification.permission === 'default') {
		await Notification.requestPermission();
	}
}

function showNotification(title: string, body: string) {
	if ('Notification' in window && Notification.permission === 'granted') {
		// Only notify if the window is not focused
		if (document.hidden) {
			new Notification(title, { body, icon: '/favicon.png' });
		}
	}
}

export async function setupEventListeners() {
	if (listenersSetup) return;
	listenersSetup = true;

	ensureNotifPermission();

	// Channel message handler
	function handleChannelMessage(payload: {
		channel_id: string;
		sender: string;
		content: string;
		timestamp: number;
	}) {
		const { channel_id, sender, content, timestamp } = payload;
		const myPubkey = get(identityStore).pubkey;
		const isOutgoing = myPubkey !== null && sender === myPubkey;
		console.log('[event] channel_message:', channel_id, sender, isOutgoing ? '(self)' : '');
		
		if (isOutgoing) return;
		
		const convos = get(conversationsStore);
		if (!convos.find(c => c.id === channel_id)) {
			upsertConversation({
				id: channel_id,
				name: `Channel ${channel_id.substring(0, 8)}`,
				type: 'group',
				unreadCount: 0,
			});
		}
		
		addMessage(channel_id, {
			id: `${channel_id}-${timestamp}-${sender.substring(0, 8)}`,
			conversationId: channel_id,
			senderPubkey: sender,
			content,
			timestamp,
			isOutgoing: false,
			status: 'delivered',
		});

		const active = get(activeConversationStore);
		if (active !== channel_id) {
			showNotification(
				displayName(sender),
				content.length > 100 ? content.substring(0, 100) + '...' : content
			);
		}
	}

	await Promise.all([
		// Auth success — global listen (this already works)
		listen<{ offline_count: number }>('auth_success', (event) => {
			console.log('[event] auth_success:', event.payload);
			reconnectAttempt = 0;
			connectionStore.update(s => ({ ...s, connected: true, reconnecting: false, error: null }));
		}),

		// Connection lost
		listen('connection_lost', () => {
			console.log('[event] connection_lost');
			connectionStore.update(s => ({ ...s, connected: false, error: 'Connection lost' }));
			scheduleReconnect();
		}),

		// Channel message
		listen<{
			channel_id: string;
			sender: string;
			content: string;
			timestamp: number;
		}>('channel_message', (event) => {
			console.log('[event] channel_message received');
			handleChannelMessage(event.payload);
		}),

		// Direct message received
		listen<{
			sender: string;
			content: string;
			timestamp: number;
		}>('direct_message', (event) => {
			const { sender, content, timestamp } = event.payload;
			console.log('[event] direct_message:', sender);
			
			upsertConversation({
				id: sender,
				name: displayName(sender),
				type: 'dm',
				unreadCount: 0,
			});
			
			addMessage(sender, {
				id: `dm-${timestamp}-${sender.substring(0, 8)}`,
				conversationId: sender,
				senderPubkey: sender,
				content,
				timestamp,
				isOutgoing: false,
				status: 'delivered',
			});

			const active = get(activeConversationStore);
			const senderName = displayName(sender);
			const preview = content.length > 80 ? content.substring(0, 80) + '...' : content;

			// In-app toast notification (always, unless viewing that conversation)
			if (active !== sender) {
				addToast(senderName, preview, sender);
			}

			// Desktop notification (when window not focused)
			showNotification(senderName, preview);
		}),

		// History loaded — backend tells us to reload messages from local DB
		listen<{ channel_id: string }>('history_loaded', (event) => {
			const { channel_id } = event.payload;
			console.log('[event] history_loaded:', channel_id);
			invoke<Message[]>('get_messages', { conversationId: channel_id }).then(dbMessages => {
				for (const msg of dbMessages) {
					addMessage(channel_id, {
						...msg,
						conversationId: channel_id,
						status: (msg.status as Message['status']) || 'delivered',
					});
				}
			}).catch(e => console.warn('[history_loaded] failed to reload messages:', e));
		}),

		// Channel created confirmation
		listen<{ channel_id: string }>('channel_created', (event) => {
			console.log('[event] channel_created:', event.payload.channel_id);
		}),

		// Channel joined confirmation
		listen<{ channel_id: string }>('channel_joined', (event) => {
			console.log('[event] channel_joined:', event.payload.channel_id);
		}),

		// Server error
		listen<{ message: string }>('server_error', (event) => {
			console.error('[event] server_error:', event.payload.message);
		}),

		// NOTE: voice_signal events are NOT handled here.  They are polled
		// via invoke('poll_voice_signals') in VoiceCall.svelte to avoid
		// double-processing (Tauri event + poll) which caused auto-reject.
	]);
}
