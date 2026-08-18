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
        bg:          '#EDE8E0',
        card:        '#FFFFFF',
        navy:        '#1A1A2E',
        danger:      '#E63946',
        safe:        '#2DC653',
        warn:        '#F4A261',
        textPrimary: '#1C1714',
        textMuted:   '#7A6F67',
        border:      '#E2DBD3',
      },
      boxShadow: {
        card:       '0 2px 16px rgba(100,80,60,0.09), 0 1px 4px rgba(100,80,60,0.06)',
        'card-hover':'0 6px 28px rgba(100,80,60,0.13), 0 2px 8px rgba(100,80,60,0.08)',
        'card-glass':'0 4px 24px rgba(100,80,60,0.10), 0 1px 6px rgba(100,80,60,0.07), inset 0 1px 0 rgba(255,255,255,0.85)',
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
