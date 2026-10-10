import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { compile } from 'svelte/compiler';
import { describe, expect, it, vi } from 'vitest';

const source = readFileSync(new URL('./OnBoarding.svelte', import.meta.url), 'utf8');
const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function controller() {
	const script = source
		.match(/<script>([\s\S]*?)<\/script>/)![1]
		.replace(/\bimport[\s\S]*?from\s+['"][^'"]+['"];?/g, '')
		.replace(/\bexport\s+/g, '')
		.replace(/\n\t\$:[\s\S]*$/, '\n');
	const code = ts.transpileModule(
		`${script}
		({ playBackgroundVideo, clearPlayOnInteraction,
		   set(v, s) { videoElement = v; show = s; } });`,
		{ compilerOptions: { target: ts.ScriptTarget.ES2022 } }
	).outputText;
	const listeners = new Map<string, Set<() => void>>();
	const document = {
		addEventListener: vi.fn((name, cb) => {
			listeners.set(name, (listeners.get(name) ?? new Set()).add(cb));
		}),
		removeEventListener: vi.fn((name, cb) => listeners.get(name)?.delete(cb))
	};
	let onDestroyCallback = () => {};
	const api = runInNewContext(code, {
		document,
		getContext: () => ({}),
		onDestroy: (cb: () => void) => (onDestroyCallback = cb)
	});
	const count = () => [...listeners.values()].reduce((n, set) => n + set.size, 0);
	const click = () => [...(listeners.get('click') ?? [])].forEach((cb) => cb());
	return { api, document, count, click, destroy: () => onDestroyCallback() };
}

const video = (play: () => Promise<void>) => ({ play: vi.fn(play) });

describe('OnBoarding background video lifecycle', () => {
	it('keeps the autoplay retry while shown and runs it once', async () => {
		const c = controller();
		const v = video(() => Promise.reject(new Error('blocked')));
		c.api.set(v, true);
		c.api.playBackgroundVideo();
		c.api.playBackgroundVideo();
		await settle();
		expect(c.count()).toBe(2);
		c.click();
		expect(v.play).toHaveBeenCalledTimes(3);
		expect(c.count()).toBe(0);
	});

	it('does not register after hide or video replacement during rejected play', async () => {
		const c = controller();
		c.api.set(
			video(() => Promise.reject(new Error('blocked'))),
			true
		);
		c.api.playBackgroundVideo();
		c.api.set(null, false);
		await settle();
		expect(c.document.addEventListener).not.toHaveBeenCalled();

		c.api.set(
			video(() => Promise.reject(new Error('blocked'))),
			true
		);
		c.api.playBackgroundVideo();
		c.api.set(
			video(() => Promise.resolve()),
			true
		);
		await settle();
		expect(c.count()).toBe(0);
	});

	it('removes listeners on hide and destroy; stale click never throws or plays', async () => {
		const c = controller();
		const v = video(() => Promise.reject(new Error('blocked')));
		c.api.set(v, true);
		c.api.playBackgroundVideo();
		await settle();
		const click = c.document.addEventListener.mock.calls[0][1];
		c.api.set(null, false);
		c.api.clearPlayOnInteraction();
		expect(c.count()).toBe(0);
		expect(() => click()).not.toThrow();
		expect(v.play).toHaveBeenCalledTimes(1);

		c.api.set(v, true);
		c.api.playBackgroundVideo();
		await settle();
		expect(c.count()).toBe(2);
		c.destroy();
		expect(c.count()).toBe(0);
		expect(c.document.removeEventListener).toHaveBeenCalledWith('touchstart', expect.any(Function));
	});

	it('compiles for client and SSR and preserves branding', () => {
		for (const generate of ['client', 'ssr'] as const) {
			expect(compile(source, { generate, filename: 'OnBoarding.svelte' }).js.code).toContain(
				'Open WebUI'
			);
		}
		expect(source).toContain('docs.openwebui.com/license');
	});
});
