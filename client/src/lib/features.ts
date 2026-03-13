/**
 * Feature flag system with unlock key validation.
 *
 * Architecture:
 * - Features are gated behind signed tokens (future: HMAC-SHA256 from payment system)
 * - For now, a hardcoded key validates locally
 * - Keys are stored in localStorage, checked on startup
 * - Feature state is reactive via Svelte stores
 *
 * Future: tokens will be `base64(nonce:expiry:tier:HMAC-SHA256(secret, nonce+expiry+tier))`
 * validated against a server-provided public key or HMAC secret.
 */

import { writable, derived, get } from 'svelte/store';

// ── Types ────────────────────────────────────────────────────────────

export type FeatureTier = 'free' | 'supporter';

export interface FeatureState {
	tier: FeatureTier;
	unlockedAt: number | null;
	key: string | null;
}

// ── Store ────────────────────────────────────────────────────────────

const STORAGE_KEY = 'mobium_feature_key';

function loadFeatureState(): FeatureState {
	try {
		const stored = localStorage.getItem(STORAGE_KEY);
		if (stored) {
			const parsed = JSON.parse(stored);
			// Re-validate the stored key
			if (parsed.key && validateKey(parsed.key)) {
				return {
					tier: 'supporter',
					unlockedAt: parsed.unlockedAt || Date.now(),
					key: parsed.key,
				};
			}
		}
	} catch { /* ignore */ }
	return { tier: 'free', unlockedAt: null, key: null };
}

export const featureStore = writable<FeatureState>(loadFeatureState());

// ── Derived feature flags ────────────────────────────────────────────

export const isDarkModeUnlocked = derived(featureStore, $f => $f.tier === 'supporter');
export const is1080pUnlocked = derived(featureStore, $f => $f.tier === 'supporter');

// ── Theme store ──────────────────────────────────────────────────────

export type ThemeMode = 'light' | 'dark';

const THEME_STORAGE_KEY = 'mobium_theme';

function loadTheme(): ThemeMode {
	try {
		const stored = localStorage.getItem(THEME_STORAGE_KEY);
		if (stored === 'dark' || stored === 'light') return stored;
	} catch { /* ignore */ }
	return 'light'; // Default to light (pastel sunset)
}

export const themeStore = writable<ThemeMode>(loadTheme());

// Subscribe to persist theme changes
themeStore.subscribe(theme => {
	try {
		localStorage.setItem(THEME_STORAGE_KEY, theme);
	} catch { /* ignore */ }
	// Apply to document
	if (typeof document !== 'undefined') {
		document.documentElement.classList.toggle('dark', theme === 'dark');
	}
});

export function toggleTheme(): void {
	const current = get(themeStore);
	const unlocked = get(isDarkModeUnlocked);
	if (current === 'light' && !unlocked) {
		// Can't switch to dark without unlock
		return;
	}
	themeStore.set(current === 'dark' ? 'light' : 'dark');
}

// ── Key validation ───────────────────────────────────────────────────

/**
 * Validate an unlock key.
 *
 * Future: this will verify HMAC-SHA256 signatures from the payment system.
 * For now, uses a hardcoded key for development.
 */
function validateKey(key: string): boolean {
	// TODO: Replace with cryptographic token validation
	// Future format: base64(nonce:expiry:tier:hmac)
	// For now, simple key check
	const normalized = key.trim().toLowerCase();
	return normalized === 'yeeyee';
}

/**
 * Attempt to unlock features with a key.
 * Returns true if the key was valid.
 */
export function redeemKey(key: string): boolean {
	if (!validateKey(key)) {
		return false;
	}

	const state: FeatureState = {
		tier: 'supporter',
		unlockedAt: Date.now(),
		key: key.trim().toLowerCase(),
	};

	featureStore.set(state);

	try {
		localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
	} catch { /* ignore */ }

	return true;
}

/**
 * Reset features to free tier.
 */
export function resetFeatures(): void {
	featureStore.set({ tier: 'free', unlockedAt: null, key: null });
	themeStore.set('light');
	try {
		localStorage.removeItem(STORAGE_KEY);
	} catch { /* ignore */ }
}

// ── Initialize theme on load ─────────────────────────────────────────

if (typeof document !== 'undefined') {
	const theme = loadTheme();
	const state = loadFeatureState();
	// If dark mode is set but not unlocked, reset to light
	if (theme === 'dark' && state.tier !== 'supporter') {
		themeStore.set('light');
	} else {
		document.documentElement.classList.toggle('dark', theme === 'dark');
	}
}
