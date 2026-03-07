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
	usernameStore,
	searchResultsStore,
	subChannelsStore,
	bansStore,
	type Message,
	type SubChannel,
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

		// DM session established (X3DH complete) — add conversation to sidebar
		listen<{ peer: string }>('dm_session_established', (event) => {
			const { peer } = event.payload;
			console.log('[event] dm_session_established:', peer);
			upsertConversation({
				id: peer,
				name: displayName(peer),
				type: 'dm',
				unreadCount: 0,
			});
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

		// ── Username & friends events ──────────────────────────

		listen<{ username: string }>('username_set', (event) => {
			const username = event.payload.username;
			usernameStore.set(username);
			console.log('[event] Username set:', username);
			addToast(`Username set: ${username}`, 'success');
		}),

		listen<{ users: Array<{ pubkey: number[]; username: string }> }>('search_results', (event) => {
			const results = (event.payload.users || []).map((u: { pubkey: number[]; username: string }) => ({
				pubkey: Array.from(u.pubkey).map((b: number) => b.toString(16).padStart(2, '0')).join(''),
				username: u.username,
			}));
			searchResultsStore.set(results);
		}),

		// ── Moderation events ──────────────────────────────────────────

		listen<{ channel_id: number[]; role: string }>('role_updated', (event) => {
			const role = event.payload.role;
			addToast(`Your role has been updated to ${role}`, 'info');
		}),

		listen<{ channel_id: number[]; reason: string }>('banned', (event) => {
			const reason = event.payload.reason;
			addToast(`You have been banned${reason ? ': ' + reason : ''}`, 'error');
		}),

		listen<{ channel_id: number[]; bans: Array<{ pubkey: number[]; reason: string | null }> }>('bans_list', (event) => {
			const bans = (event.payload.bans || []).map((b: { pubkey: number[]; reason: string | null }) => ({
				pubkey: Array.from(b.pubkey).map((v: number) => v.toString(16).padStart(2, '0')).join(''),
				reason: b.reason,
			}));
			bansStore.set(bans);
		}),

		listen<{ channel_id: number[]; target_pubkey: number[] }>('user_banned', () => {
			addToast('User has been banned', 'success');
		}),

		listen<{ channel_id: number[]; target_pubkey: number[] }>('user_unbanned', () => {
			addToast('User has been unbanned', 'success');
		}),

		listen<{ channel_id: number[]; target_pubkey: number[]; role: string }>('role_set', (event) => {
			addToast(`Role updated to ${event.payload.role}`, 'success');
		}),

		// ── Sub-channel events ─────────────────────────────────────────

		listen<{ channel_id: number[]; sub_channels: Array<{ id: number[]; name: string; kind: string; position: number }> }>('sub_channels_list', (event) => {
			const channelHex = Array.from(event.payload.channel_id).map((b: number) => b.toString(16).padStart(2, '0')).join('');
			const subs: SubChannel[] = (event.payload.sub_channels || []).map((s: { id: number[]; name: string; kind: string; position: number }) => ({
				id: Array.from(s.id).map((b: number) => b.toString(16).padStart(2, '0')).join(''),
				name: s.name,
				kind: s.kind as 'text' | 'voice',
				position: s.position,
			}));
			subChannelsStore.update(m => { const nm = new Map(m); nm.set(channelHex, subs); return nm; });
		}),

		listen<{ channel_id: number[]; sub_channel_id: number[]; name: string; kind: string; position: number }>('sub_channel_created', (event) => {
			const channelHex = Array.from(event.payload.channel_id).map((b: number) => b.toString(16).padStart(2, '0')).join('');
			const sub: SubChannel = {
				id: Array.from(event.payload.sub_channel_id).map((b: number) => b.toString(16).padStart(2, '0')).join(''),
				name: event.payload.name,
				kind: event.payload.kind as 'text' | 'voice',
				position: event.payload.position,
			};
			subChannelsStore.update(m => {
				const nm = new Map(m);
				const existing = nm.get(channelHex) || [];
				nm.set(channelHex, [...existing, sub].sort((a, b) => a.position - b.position));
				return nm;
			});
			addToast(`Sub-channel "${sub.name}" created`, 'info');
		}),

		listen<{ channel_id: number[]; sub_channel_id: number[] }>('sub_channel_deleted', (event) => {
			const channelHex = Array.from(event.payload.channel_id).map((b: number) => b.toString(16).padStart(2, '0')).join('');
			const subHex = Array.from(event.payload.sub_channel_id).map((b: number) => b.toString(16).padStart(2, '0')).join('');
			subChannelsStore.update(m => {
				const nm = new Map(m);
				const existing = nm.get(channelHex) || [];
				nm.set(channelHex, existing.filter(s => s.id !== subHex));
				return nm;
			});
			addToast('Sub-channel deleted', 'info');
		}),

		listen<{ channel_id: number[]; has_password: boolean }>('channel_password_set', (event) => {
			addToast(event.payload.has_password ? 'Channel password set' : 'Channel password cleared', 'success');
		}),

		// ── Server errors with codes ───────────────────────────────────

		listen<{ message: string; code?: string }>('server_error', (event) => {
			const { message, code } = event.payload;
			if (code === 'banned') {
				addToast(message, 'error');
			} else if (code === 'password_required') {
				addToast(message, 'error');
			} else {
				addToast(`Server error: ${message}`, 'error');
			}
		}),

		// NOTE: voice_signal events are NOT handled here.  They are polled
		// via invoke('poll_voice_signals') in VoiceCall.svelte to avoid
		// double-processing (Tauri event + poll) which caused auto-reject.
	]);
}
