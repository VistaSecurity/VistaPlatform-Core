/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      // Surface the operator design-token CSS variables to Tailwind utilities
      // (e.g. bg-op-panel / text-t1) alongside the ported .op-* component classes.
      colors: {
        op: {
          bg: 'var(--op-bg)', bg2: 'var(--op-bg2)', panel: 'var(--op-panel)', panel2: 'var(--op-panel2)',
          border: 'var(--op-border)', border2: 'var(--op-border2)', accent: 'var(--op-accent)',
        },
        t1: 'var(--op-t1)', t2: 'var(--op-t2)', t3: 'var(--op-t3)',
        accent: 'var(--accent)', blue: 'var(--vista-blue)',
      },
      fontFamily: {
        head: 'var(--font-head)', body: 'var(--font-body)', label: 'var(--font-label)', display: 'var(--font-display)',
      },
    },
  },
  plugins: [],
};
