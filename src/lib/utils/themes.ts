import { derived } from 'svelte/store';
import { theme } from '$lib/stores';
import { WEBUI_BASE_URL } from '$lib/constants';

/**
 * Salas O'Brien theme constants
 */
export const SO_THEME_ID = 'salas-obrien';

/**
 * Check if a theme string is the Salas O'Brien theme
 */
export function isSalasObrienTheme(themeName: string): boolean {
	return themeName === SO_THEME_ID;
}

/**
 * Get the base path for theme-specific static assets.
 * Returns the themed path if the theme has custom assets, otherwise the default path.
 */
export function getThemeStaticBase(themeName: string): string {
	if (isSalasObrienTheme(themeName)) {
		return `${WEBUI_BASE_URL}/static/themes/salas-obrien`;
	}
	return `${WEBUI_BASE_URL}/static`;
}

/**
 * Get the icon/asset path for a given theme.
 * Falls back to default if the theme doesn't have custom assets.
 */
export function getThemeIconPath(themeName: string, iconName: string): string {
	return `${getThemeStaticBase(themeName)}/${iconName}`;
}

/**
 * Derived store that provides the current theme's static asset base path.
 */
export const themeStaticBase = derived(theme, ($theme) => getThemeStaticBase($theme));

/**
 * Derived store that provides common icon paths based on the active theme.
 */
export const themeIcons = derived(theme, ($theme) => {
	const base = getThemeStaticBase($theme);
	return {
		favicon: `${base}/favicon.png`,
		faviconDark: `${base}/favicon-dark.png`,
		favicon96: `${base}/favicon-96x96.png`,
		faviconSvg: `${base}/favicon.svg`,
		faviconIco: `${base}/favicon.ico`,
		logo: `${base}/logo.png`,
		splash: `${base}/splash.png`,
		splashDark: `${base}/splash-dark.png`,
		appleTouchIcon: `${base}/apple-touch-icon.png`,
		manifest192: `${base}/web-app-manifest-192x192.png`,
		manifest512: `${base}/web-app-manifest-512x512.png`
	};
});

/**
 * Determine the effective dark/light mode for the Salas O'Brien theme.
 * The SO theme auto-detects from system preference.
 */
export function getSalasObrienMode(): 'dark' | 'light' {
	if (typeof window !== 'undefined') {
		return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
	}
	return 'light';
}
