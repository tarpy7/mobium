/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte,ts}'],
	theme: {
		extend: {
			colors: {
				primary: {
					DEFAULT: '#e07a5f',  // Warm terracotta
					dark: '#c96a50',
					light: '#f2a68d',
				},
				accent: {
					DEFAULT: '#81b29a',  // Sage green
					dark: '#6a9a82',
					light: '#a8d5ba',
				},
				secondary: '#b8a9c9', // Lavender
				success: '#81b29a',    // Sage (same as accent)
				danger: '#e07a7a',     // Soft coral red
				warning: '#f2cc8f',    // Warm sand
				background: '#1a1625', // Deep plum-black
				surface: {
					DEFAULT: '#2a2435', // Dark plum
					light: '#3d3548',   // Lighter plum
				},
				text: {
					DEFAULT: '#f4f0f7', // Warm white
					muted: '#9b8fb0',   // Muted lavender
				},
			},
			backgroundImage: {
				'sunset-gradient': 'linear-gradient(135deg, #2a2435 0%, #1a1625 50%, #231d2e 100%)',
			},
		}
	},
	plugins: []
};
