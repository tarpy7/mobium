import { writable, derived, get } from 'svelte/store';

export interface ConnectionStatus {
	connected: boolean;
	serverUrl: string | null;
	error: string | null;
	reconnecting: boolean;
}

export const connectionStore = writable<ConnectionStatus>({
	connected: false,
	serverUrl: null,
	error: null,
	reconnecting: false
});

export interface Conversation {
	id: string;
	name: string;
	type: 'dm' | 'group';
	lastMessage?: string;
	lastMessageAt?: number;
	unreadCount: number;
}

export const conversationsStore = writable<Conversation[]>([]);

export interface Message {
	id: string;
	conversationId: string;
	senderPubkey: string;
	content: string;
	timestamp: number;
	isOutgoing: boolean;
	status: 'sending' | 'sent' | 'delivered' | 'error';
}

export const messagesStore = writable<Map<string, Message[]>>(new Map());

export const activeConversationStore = writable<string | null>(null);

export const identityStore = writable<{
	pubkey: string | null;
	mnemonicBackedUp: boolean;
}>({
	pubkey: null,
	mnemonicBackedUp: false
});

/** Nickname map: pubkey -> display name */
export const nicknamesStore = writable<Map<string, string>>(new Map());

/** Get display name for a pubkey */
export function displayName(pubkey: string): string {
	const nicknames = get(nicknamesStore);
	const nick = nicknames.get(pubkey);
	if (nick) return nick;
	if (pubkey === 'self') return 'You';
	if (pubkey.length > 16) return `${pubkey.substring(0, 6)}...${pubkey.substring(pubkey.length - 4)}`;
	return pubkey;
}

/** Add a message to a conversation */
export function addMessage(conversationId: string, message: Message) {
	console.log('[addMessage]', conversationId, message.id, message.senderPubkey, message.content?.substring(0, 30), message.isOutgoing);
	messagesStore.update(store => {
		const existing = store.get(conversationId) || [];
		// Avoid duplicates by ID
		if (existing.find(m => m.id === message.id)) {
			console.log('[addMessage] SKIP: duplicate ID', message.id);
			return store;
		}
		// Also dedup by content + approximate timestamp + sender to catch
		// the same message added optimistically (local-*) and then loaded
		// from the DB (uuid).  Timestamps may differ by up to 10s due to
		// the DB using second-precision and the frontend using milliseconds.
		const contentDup = existing.find(m =>
			m.content === message.content &&
			m.senderPubkey === message.senderPubkey &&
			Math.abs(m.timestamp - message.timestamp) < 10_000
		);
		if (contentDup) {
			console.log('[addMessage] SKIP: content dedup matched', contentDup.id, 'ts diff', Math.abs(contentDup.timestamp - message.timestamp));
			return store;
		}
		// Create a new array (immutable update for Svelte reactivity)
		const updated = [...existing, message].sort((a, b) => a.timestamp - b.timestamp);
		const newStore = new Map(store);
		newStore.set(conversationId, updated);
		return newStore;
	});

	// Update conversation last message
	conversationsStore.update(convos => {
		const idx = convos.findIndex(c => c.id === conversationId);
		if (idx >= 0) {
			convos[idx].lastMessage = message.content.substring(0, 100);
			convos[idx].lastMessageAt = message.timestamp;
			// Increment unread if not the active conversation
			const active = get(activeConversationStore);
			if (active !== conversationId && !message.isOutgoing) {
				convos[idx].unreadCount = (convos[idx].unreadCount || 0) + 1;
			}
		}
		return [...convos];
	});
}

/** Add or update a conversation */
export function upsertConversation(conversation: Conversation) {
	conversationsStore.update(convos => {
		const idx = convos.findIndex(c => c.id === conversation.id);
		if (idx >= 0) {
			convos[idx] = { ...convos[idx], ...conversation };
			return [...convos];
		}
		return [...convos, conversation];
	});
}

// ── Sidebar filter ──────────────────────────────────────────────────
export type SidebarFilter = 'all' | 'dms' | 'channels';
export const sidebarFilterStore = writable<SidebarFilter>('all');

// ── Toast notifications ─────────────────────────────────────────────
export interface Toast {
	id: string;
	title: string;
	body: string;
	conversationId: string;
	timestamp: number;
}

export const toastStore = writable<Toast[]>([]);

let toastCounter = 0;

export function addToast(title: string, body: string, conversationId: string) {
	const id = `toast-${++toastCounter}-${Date.now()}`;
	const toast: Toast = { id, title, body, conversationId, timestamp: Date.now() };
	toastStore.update(toasts => [...toasts, toast]);
	// Auto-dismiss after 5 seconds
	setTimeout(() => dismissToast(id), 5000);
}

export function dismissToast(id: string) {
	toastStore.update(toasts => toasts.filter(t => t.id !== id));
}

/** Clear unread count for a conversation */
export function clearUnread(conversationId: string) {
	conversationsStore.update(convos => {
		const idx = convos.findIndex(c => c.id === conversationId);
		if (idx >= 0 && convos[idx].unreadCount > 0) {
			convos[idx].unreadCount = 0;
			return [...convos];
		}
		return convos;
	});
}

// ── Voice call state ────────────────────────────────────────────────
export type VoiceCallState = 'idle' | 'ringing_out' | 'ringing_in' | 'connecting' | 'active' | 'ended';

export interface VoiceCall {
	state: VoiceCallState;
	peerPubkey: string | null;
	startTime: number | null;
	muted: boolean;
	error: string | null;
	/** Whether we are sharing our screen */
	screenSharing: boolean;
	/** Whether the remote peer is sharing their screen */
	remoteScreenSharing: boolean;
}

export const voiceCallStore = writable<VoiceCall>({
	state: 'idle',
	peerPubkey: null,
	startTime: null,
	muted: false,
	error: null,
	screenSharing: false,
	remoteScreenSharing: false,
});

// ── Channel voice chat state ────────────────────────────────────────
export type ScreenQuality = 'low' | 'medium' | 'high';

export interface ChannelVoiceState {
	channelId: string | null;
	participants: string[];
	muted: boolean;
	/** Whether we are sharing our screen to the channel */
	screenSharing: boolean;
	/** Active screen share quality preset (null if not sharing) */
	screenQuality: ScreenQuality | null;
	/** Pubkey hex of the participant currently sharing their screen (null if none) */
	remoteScreenSharer: string | null;
}

export const channelVoiceStore = writable<ChannelVoiceState>({
	channelId: null,
	participants: [],
	muted: false,
	screenSharing: false,
	screenQuality: null,
	remoteScreenSharer: null,
});
