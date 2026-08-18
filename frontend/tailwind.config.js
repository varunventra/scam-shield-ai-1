export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Consolas', 'monospace'],
      },
      colors: {
        bg: '#EEF1F4',
        card: '#FFFFFF',
        navy: '#1A1A2E',
        danger: '#E63946',
        safe: '#2DC653',
        warn: '#F4A261',
        textPrimary: '#111111',
        textMuted: '#8A8A8A',
        border: '#EEEEEE',
        // Dark mode palette
        dark: {
          bg:      '#0F1117',
          surface: '#1A1D27',
          card:    '#20243A',
          border:  '#2A2D3E',
          text:    '#E8EAF0',
          muted:   '#6B7280',
          accent:  '#3B82F6',
        },
      },
      boxShadow: {
        card: '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)',
        'card-hover': '0 4px 12px rgba(0,0,0,0.08)',
      },
      borderRadius: { '2xl': '16px', '3xl': '24px' },
      keyframes: {
        bounce3: { '0%,80%,100%': { transform: 'translateY(0)' }, '40%': { transform: 'translateY(-6px)' } },
      },
      animation: { bounce3: 'bounce3 1.2s ease-in-out infinite' },
    },
  },
  plugins: [],
}
