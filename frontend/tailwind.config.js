export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Samsung Sans"', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Consolas', 'monospace'],
      },
      colors: {
        bg:          '#EFECE6',
        card:        '#FFFFFF',
        accent:      '#2563EB',
        danger:      '#DC2626',
        safe:        '#16A34A',
        warn:        '#D97706',
        textPrimary: '#0D0D0D',
        textMuted:   '#6B7280',
        textFaint:   '#B0A99E',
        border:      'rgba(0,0,0,0.07)',
      },
      boxShadow: {
        card:       'inset 0 1px 0 rgba(255,255,255,0.95), 0 1px 3px rgba(0,0,0,0.04), 0 4px 16px rgba(0,0,0,0.06)',
        'card-hover':'inset 0 1px 0 rgba(255,255,255,0.95), 0 2px 6px rgba(0,0,0,0.06), 0 8px 28px rgba(0,0,0,0.09)',
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
