/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	theme: {
		extend: {
			colors: {
				primary: {
					DEFAULT: '#3b82f6',
					dark: '#2563eb'
				},
				secondary: '#64748b',
				success: '#22c55e',
				danger: '#ef4444',
				warning: '#f59e0b',
				background: '#0f172a',
				surface: {
					DEFAULT: '#1e293b',
					light: '#334155'
				},
				text: {
					DEFAULT: '#f8fafc',
					muted: '#94a3b8'
				}
			}
		}
	},
	plugins: []
};