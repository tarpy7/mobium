// Disable SSR for the entire app - required for Tauri
// prerender generates a static index.html, ssr=false means no server-side rendering
export const ssr = false;
export const prerender = true;
