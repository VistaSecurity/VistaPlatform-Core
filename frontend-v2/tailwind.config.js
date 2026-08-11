/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // Surface the design-token CSS variables to Tailwind utilities so we can
      // use e.g. bg-panel / text-t1 alongside the ported component classes.
      colors: {
        app: { bg: 'var(--app-bg)', panel: 'var(--app-panel)', panel2: 'var(--app-panel2)', border: 'var(--app-border)' },
        t1: 'var(--app-t1)', t2: 'var(--app-t2)', t3: 'var(--app-t3)',
        accent: 'var(--accent)',
      },
    },
  },
  plugins: [],
};
