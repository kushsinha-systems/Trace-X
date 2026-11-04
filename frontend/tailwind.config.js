/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          bg: '#070910',      // app background (under glow layers)
          panel: '#0e121b',   // solid card fallback
          panel2: '#141926',  // raised / hover / nested
          border: '#1e2533',  // 1px borders
          line: '#161b27',    // grid lines, lane rules
          text: '#e8ecf4',    // primary text
          muted: '#8e97ab',   // secondary text
          faint: '#5a6377',   // tertiary / placeholders
        },
        accent: {
          DEFAULT: '#5b9cff', // primary accent (tabs, links, correlated edges)
          2: '#8b7bff',       // gradient partner
          cyan: '#38d6f5',
        },
        sev: {
          high: '#ff6b6b',    // HIGH — red
          med: '#fbbf24',     // MEDIUM — amber
          low: '#60a5db',     // LOW — muted blue
        },
      },
      fontFamily: {
        // Offline-safe stacks: no webfont downloads, same look everywhere.
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      borderRadius: { card: '14px' },
      keyframes: {
        'fade-up': { from: { opacity: 0, transform: 'translateY(6px)' }, to: { opacity: 1, transform: 'none' } },
        shimmer: { from: { backgroundPosition: '-400px 0' }, to: { backgroundPosition: '400px 0' } },
        ping2: { '0%': { transform: 'scale(1)', opacity: 0.6 }, '80%,100%': { transform: 'scale(2.4)', opacity: 0 } },
        'pill-swap': { from: { opacity: 0, transform: 'translateY(9px)', filter: 'blur(3px)' }, to: { opacity: 1, transform: 'none', filter: 'none' } },
        sweep: { from: { transform: 'translateX(-120%)' }, to: { transform: 'translateX(320%)' } },
      },
      animation: {
        'fade-up': 'fade-up .35s ease-out both',
        shimmer: 'shimmer 1.4s linear infinite',
        ping2: 'ping2 1.8s cubic-bezier(0,0,.2,1) infinite',
        'pill-swap': 'pill-swap .45s cubic-bezier(.2,.8,.2,1) both',
        sweep: 'sweep 2.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
