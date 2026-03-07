/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	darkMode: 'class',
	theme: {
		extend: {
			colors: {
				primary: {
					DEFAULT: '#e07a5f',
					dark: '#c96a50',
					light: '#f2a68d',
				},
				accent: {
					DEFAULT: '#81b29a',
					dark: '#6a9a82',
					light: '#a8d5ba',
				},
				secondary: '#b8a9c9',
				lavender: '#b8a9c9',
				success: '#81b29a',
				danger: '#e07a7a',
				warning: '#f2cc8f',
				background: 'var(--bg)',
				surface: {
					DEFAULT: 'var(--surface)',
					light: 'var(--surface-light)',
				},
				text: {
					DEFAULT: 'var(--text)',
					muted: 'var(--text-muted)',
				},
			},
			backgroundImage: {
				'sunset-gradient': 'var(--sunset-gradient)',
			},
		}
	},
	plugins: [],
};
