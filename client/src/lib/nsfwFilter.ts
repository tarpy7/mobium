/**
 * Client-side NSFW content filter.
 *
 * Uses NSFWJS (TensorFlow.js) to classify images and video frames locally.
 * All processing happens on-device — no data leaves the client.
 *
 * Classification categories (NSFWJS):
 *   - Porn: Explicit sexual content
 *   - Sexy: Suggestive but not explicit
 *   - Hentai: Animated/drawn explicit content
 *   - Drawing: Non-explicit illustrations
 *   - Neutral: Safe content
 *
 * We block: Porn, Hentai, and high-confidence Sexy content.
 */

import * as nsfwjs from 'nsfwjs';
import * as tf from '@tensorflow/tfjs';
import { writable, get } from 'svelte/store';

// ── Configuration ────────────────────────────────────────────────────

/** Thresholds for blocking content. Values 0-1 (probability). */
const THRESHOLDS = {
	Porn: 0.3,      // Very aggressive — block even low-confidence porn
	Hentai: 0.3,    // Same for drawn explicit content
	Sexy: 0.7,      // Only block high-confidence suggestive content
};

/** How many frames to sample from a video for classification */
const VIDEO_SAMPLE_FRAMES = 6;

/** Max dimension to resize images to before classification (performance) */
const MAX_CLASSIFY_DIM = 299;

/** Video frame sample interval in seconds */
const VIDEO_SAMPLE_INTERVAL_SEC = 5;

// ── State ────────────────────────────────────────────────────────────

let model: nsfwjs.NSFWJS | null = null;
let modelLoading = false;

/** Whether the NSFW filter is enabled (persisted via store) */
export const nsfwFilterEnabled = writable<boolean>(true);

/** Filter loading state */
export const nsfwFilterReady = writable<boolean>(false);

export interface NsfwResult {
	blocked: boolean;
	reason: string | null;
	scores: Record<string, number>;
}

// ── Model Management ─────────────────────────────────────────────────

/**
 * Load the NSFWJS model. Called lazily on first classification.
 * Uses the MobileNetV2 model (small, fast, ~3MB).
 */
async function loadModel(): Promise<nsfwjs.NSFWJS> {
	if (model) return model;
	if (modelLoading) {
		// Wait for ongoing load
		while (modelLoading) {
			await new Promise(r => setTimeout(r, 100));
		}
		if (model) return model;
	}

	modelLoading = true;
	try {
		// Use the smaller MobileNetV2 model for performance
		// Loads from CDN on first use, then cached by the browser
		await tf.ready();

		// Set WebGL backend for GPU acceleration if available, fallback to CPU
		try {
			await tf.setBackend('webgl');
		} catch {
			console.warn('[nsfw] WebGL not available, falling back to CPU');
			await tf.setBackend('cpu');
		}

		model = await nsfwjs.load(
			'https://cdn.jsdelivr.net/npm/nsfwjs@4/dist/model/',
			{ type: 'graph', size: 299 }
		);
		nsfwFilterReady.set(true);
		console.log('[nsfw] Model loaded successfully');
		return model;
	} catch (e) {
		console.error('[nsfw] Failed to load model:', e);
		throw e;
	} finally {
		modelLoading = false;
	}
}

// ── Image Classification ─────────────────────────────────────────────

/**
 * Classify a single image and determine if it should be blocked.
 * Accepts: File, Blob, HTMLImageElement, ImageBitmap, or data URL string.
 */
export async function classifyImage(
	input: File | Blob | HTMLImageElement | ImageBitmap | string
): Promise<NsfwResult> {
	if (!get(nsfwFilterEnabled)) {
		return { blocked: false, reason: null, scores: {} };
	}

	const nsfwModel = await loadModel();
	const img = await toImageElement(input);

	const predictions = await nsfwModel.classify(img);

	const scores: Record<string, number> = {};
	for (const p of predictions) {
		scores[p.className] = p.probability;
	}

	return evaluateScores(scores);
}

/**
 * Classify image data from an ArrayBuffer (e.g., received file chunk).
 */
export async function classifyImageBuffer(buffer: ArrayBuffer, mimeType: string): Promise<NsfwResult> {
	if (!get(nsfwFilterEnabled)) {
		return { blocked: false, reason: null, scores: {} };
	}

	const blob = new Blob([buffer], { type: mimeType });
	return classifyImage(blob);
}

// ── Video Classification ─────────────────────────────────────────────

/**
 * Classify a video by sampling frames at intervals.
 * If ANY frame is flagged, the entire video is blocked.
 * Accepts: File or Blob.
 */
export async function classifyVideo(input: File | Blob): Promise<NsfwResult> {
	if (!get(nsfwFilterEnabled)) {
		return { blocked: false, reason: null, scores: {} };
	}

	const nsfwModel = await loadModel();
	const url = URL.createObjectURL(input);

	try {
		const video = document.createElement('video');
		video.muted = true;
		video.playsInline = true;
		video.preload = 'auto';
		video.src = url;

		// Wait for metadata to load
		await new Promise<void>((resolve, reject) => {
			video.onloadedmetadata = () => resolve();
			video.onerror = () => reject(new Error('Failed to load video'));
			setTimeout(() => reject(new Error('Video load timeout')), 15000);
		});

		const duration = video.duration;
		if (!duration || !isFinite(duration)) {
			return { blocked: false, reason: null, scores: {} };
		}

		// Sample frames at regular intervals
		const interval = Math.max(1, duration / (VIDEO_SAMPLE_FRAMES + 1));
		const worstScores: Record<string, number> = {};

		for (let i = 1; i <= VIDEO_SAMPLE_FRAMES && i * interval < duration; i++) {
			const time = i * interval;
			const frame = await extractVideoFrame(video, time);
			if (!frame) continue;

			const predictions = await nsfwModel.classify(frame);
			for (const p of predictions) {
				if (!worstScores[p.className] || p.probability > worstScores[p.className]) {
					worstScores[p.className] = p.probability;
				}
			}

			// Early exit: if any frame is clearly NSFW, don't waste time on rest
			const earlyResult = evaluateScores(worstScores);
			if (earlyResult.blocked) {
				console.log(`[nsfw] Video blocked early at frame ${i}/${VIDEO_SAMPLE_FRAMES}`);
				return earlyResult;
			}
		}

		return evaluateScores(worstScores);
	} finally {
		URL.revokeObjectURL(url);
	}
}

/**
 * Extract a single frame from a video at the given time (seconds).
 * Returns an HTMLCanvasElement suitable for NSFWJS classification.
 */
async function extractVideoFrame(
	video: HTMLVideoElement,
	timeSec: number,
): Promise<HTMLCanvasElement | null> {
	return new Promise((resolve) => {
		video.currentTime = timeSec;
		video.onseeked = () => {
			try {
				const canvas = document.createElement('canvas');
				// Scale down for performance
				const scale = Math.min(1, MAX_CLASSIFY_DIM / Math.max(video.videoWidth, video.videoHeight));
				canvas.width = Math.round(video.videoWidth * scale);
				canvas.height = Math.round(video.videoHeight * scale);
				const ctx = canvas.getContext('2d');
				if (!ctx) { resolve(null); return; }
				ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
				resolve(canvas);
			} catch {
				resolve(null);
			}
		};
		// Timeout for seek
		setTimeout(() => resolve(null), 5000);
	});
}

// ── Classification for Files ─────────────────────────────────────────

/**
 * Classify any file — routes to image or video classifier based on MIME type.
 * Returns { blocked, reason, scores }.
 *
 * For non-image/video files, returns { blocked: false }.
 */
export async function classifyFile(file: File): Promise<NsfwResult> {
	if (!get(nsfwFilterEnabled)) {
		return { blocked: false, reason: null, scores: {} };
	}

	const type = file.type.toLowerCase();

	if (type.startsWith('image/')) {
		return classifyImage(file);
	}

	if (type.startsWith('video/')) {
		return classifyVideo(file);
	}

	// Non-visual files are always allowed
	return { blocked: false, reason: null, scores: {} };
}

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Convert various input types to an HTMLImageElement for NSFWJS.
 */
async function toImageElement(
	input: File | Blob | HTMLImageElement | ImageBitmap | string
): Promise<HTMLImageElement | HTMLCanvasElement> {
	if (input instanceof HTMLImageElement) {
		// Already an image element — ensure it's loaded
		if (!input.complete) {
			await new Promise<void>((resolve) => {
				input.onload = () => resolve();
				input.onerror = () => resolve();
			});
		}
		return input;
	}

	if (input instanceof ImageBitmap) {
		// Draw to canvas
		const canvas = document.createElement('canvas');
		const scale = Math.min(1, MAX_CLASSIFY_DIM / Math.max(input.width, input.height));
		canvas.width = Math.round(input.width * scale);
		canvas.height = Math.round(input.height * scale);
		const ctx = canvas.getContext('2d')!;
		ctx.drawImage(input, 0, 0, canvas.width, canvas.height);
		return canvas as any;
	}

	// File, Blob, or data URL string → load as HTMLImageElement
	const url = typeof input === 'string' ? input : URL.createObjectURL(input);
	const img = new Image();
	img.crossOrigin = 'anonymous';

	try {
		await new Promise<void>((resolve, reject) => {
			img.onload = () => resolve();
			img.onerror = () => reject(new Error('Failed to load image'));
			img.src = url;
		});
		return img;
	} finally {
		if (typeof input !== 'string') {
			URL.revokeObjectURL(url);
		}
	}
}

/**
 * Evaluate classification scores against thresholds.
 */
function evaluateScores(scores: Record<string, number>): NsfwResult {
	const reasons: string[] = [];

	for (const [category, threshold] of Object.entries(THRESHOLDS)) {
		const score = scores[category] || 0;
		if (score >= threshold) {
			reasons.push(`${category} (${(score * 100).toFixed(0)}%)`);
		}
	}

	if (reasons.length > 0) {
		return {
			blocked: true,
			reason: `Content blocked: ${reasons.join(', ')}`,
			scores,
		};
	}

	return { blocked: false, reason: null, scores };
}

/**
 * Pre-load the NSFW model (call during app init for faster first classification).
 */
export async function preloadModel(): Promise<void> {
	try {
		await loadModel();
	} catch (e) {
		console.warn('[nsfw] Model preload failed — will retry on first use:', e);
	}
}
