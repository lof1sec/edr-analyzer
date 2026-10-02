import { useCallback, useEffect, useState } from 'react';

const STORAGE_KEY = 'edr-theme';
const THEMES = ['light', 'dark', 'system'];

function getSystemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function resolveTheme(theme) {
  return theme === 'system' ? getSystemTheme() : theme;
}

function applyTheme(theme) {
  const resolved = resolveTheme(theme);
  document.documentElement.classList.toggle('dark', resolved === 'dark');
  return resolved;
}

/**
 * Theme controller: `light` | `dark` | `system`, persisted in localStorage.
 *
 * The `dark` class on <html> drives every Tailwind `dark:` variant. An inline
 * script in index.html applies the same logic before first paint to avoid a
 * flash of the wrong theme.
 */
export function useTheme() {
  const [theme, setTheme] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    return THEMES.includes(stored) ? stored : 'system';
  });

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, theme);
    applyTheme(theme);

    if (theme !== 'system') return undefined;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => applyTheme('system');
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [theme]);

  const cycleTheme = useCallback(() => {
    setTheme((current) => THEMES[(THEMES.indexOf(current) + 1) % THEMES.length]);
  }, []);

  return { theme, setTheme, cycleTheme, resolvedTheme: resolveTheme(theme) };
}
