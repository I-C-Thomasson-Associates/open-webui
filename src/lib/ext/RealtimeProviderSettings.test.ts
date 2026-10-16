import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { readable } from 'svelte/store';
import { render } from 'svelte/server';
import RealtimeProviderSettings, {
	REALTIME_PRESETS,
	applyEngine,
	normalizeEngine,
	providerFor,
	type RealtimeSettings
} from './RealtimeProviderSettings.svelte';

const source = readFileSync(new URL('./RealtimeProviderSettings.svelte', import.meta.url), 'utf-8');
const audio = readFileSync(
	new URL('../components/admin/Settings/Audio.svelte', import.meta.url),
	'utf-8'
);

const custom: RealtimeSettings = {
	PROVIDER: 'azure',
	AUTH_TYPE: 'api_key',
	OPENAI_API_BASE_URL: 'https://custom.example/openai/v1',
	OPENAI_API_KEY: 'secret-key',
	MODEL: 'my-deployment',
	VOICE: 'verse',
	TRANSCRIPTION_MODEL: 'my-stt',
	REALTIME_CALL_PROMPT_TEMPLATE: 'be brief'
};

const html = (realtime: RealtimeSettings) =>
	render(RealtimeProviderSettings, {
		props: { realtime },
		context: new Map([['i18n', readable({ t: (k: string) => k })]])
	}).body;

describe('RealtimeProviderSettings', () => {
	it('defaults missing or unknown engines to openai', () => {
		expect(normalizeEngine(undefined)).toBe('openai');
		expect(normalizeEngine('bogus')).toBe('openai');
		expect(normalizeEngine('azure')).toBe('azure');
		expect(normalizeEngine('openrouter')).toBe('openrouter');
	});

	it('rendering preserves loaded custom fields (no reset)', () => {
		const copy = { ...custom };
		const out = html(copy);
		expect(copy).toEqual(custom);
		for (const v of [
			'https://custom.example/openai/v1',
			'my-deployment',
			'verse',
			'my-stt',
			'be brief'
		]) {
			expect(out).toContain(v);
		}
		expect(out).toContain('Azure model deployment');
	});

	it('engine change always clears the API key', () => {
		for (const e of ['openai', 'azure', 'openrouter']) {
			expect(applyEngine(custom, e).OPENAI_API_KEY).toBe('');
		}
	});

	it('explicit switch applies the selected defaults and keeps other fields', () => {
		const or = applyEngine(custom, 'openrouter');
		expect(or).toMatchObject({
			PROVIDER: 'openrouter',
			AUTH_TYPE: 'api_key',
			OPENAI_API_BASE_URL: 'https://openrouter.ai/api/v1',
			MODEL: 'openai/gpt-4o-audio-preview',
			VOICE: 'alloy',
			TRANSCRIPTION_MODEL: 'google/gemini-2.5-flash',
			REALTIME_CALL_PROMPT_TEMPLATE: 'be brief'
		});
		const az = applyEngine(or, 'azure');
		expect(az).toMatchObject({
			MODEL: 'gpt-realtime',
			VOICE: 'alloy',
			TRANSCRIPTION_MODEL: 'whisper-1'
		});
		expect(az.OPENAI_API_BASE_URL).toBe('');
		expect(applyEngine(az, 'openai')).toMatchObject({
			OPENAI_API_BASE_URL: REALTIME_PRESETS.openai.base,
			MODEL: 'gpt-realtime-2.1-mini'
		});
	});

	it('shows truthful OpenRouter text and Azure placeholder', () => {
		const or = html({ ...custom, PROVIDER: 'openrouter' });
		expect(or).toContain('Turn-based, not native realtime');
		expect(or).toContain('ignores the Realtime prompt template');
		expect(or).toContain('Input audio chat model');
		expect(html({ ...custom, PROVIDER: 'azure', OPENAI_API_BASE_URL: '' })).toContain(
			'https://resource.openai.azure.com/openai/v1'
		);
	});

	it('provider select is labelled and only a change event applies presets', () => {
		expect(html(custom)).toMatch(/<select[^>]*aria-label="Realtime provider"/);
		expect(source).toContain('on:change={onEngineChange}');
		expect(source).not.toMatch(/\$:[^\n]*applyEngine/);
	});

	it('migrates legacy settings without overriding explicit PROVIDER', () => {
		expect(providerFor({ ENGINE: 'azure' })).toBe('azure');
		expect(providerFor({ ENGINE: 'openrouter' })).toBe('openrouter');
		expect(providerFor({ ENGINE: 'openrouter', PROVIDER: 'openai' })).toBe('openai');
		const switched = applyEngine({ ...custom, ENGINE: 'azure', AUTH_TYPE: 'microsoft_entra_id' }, 'openrouter');
		expect(switched).not.toHaveProperty('ENGINE');
		expect(switched.AUTH_TYPE).toBe('api_key');
		expect(switched.OPENAI_API_KEY).toBe('');
	});

	it('supports upstream Entra authentication without displaying an API key input', () => {
		const entra = html({ ...custom, AUTH_TYPE: 'microsoft_entra_id' });
		expect(entra).toContain('microsoft_entra_id');
		expect(entra).toContain('settings.audio.realtime.entraHelp');
		expect(entra).not.toMatch(/<input[^>]*type="password"/);
		expect(source).not.toContain('no Microsoft Entra');
	});

	it('Audio.svelte uses the component and saves the provider and upstream input parameters', () => {
		expect(audio).toContain('<RealtimeProviderSettings bind:realtime');
		expect(audio).toContain('PROVIDER: providerFor(res.realtime ?? {})');
		expect(audio).toContain("PROVIDER: 'openai'");
		expect(audio).toContain('bind:value={REALTIME_INPUT_PARAMS}');
		expect(audio).toContain('INPUT_PARAMS: realtimeInputParams');
		expect(audio).toContain('Realtime / turn-based');
		expect(audio).not.toContain('bind:value={realtime.OPENAI_API_KEY}');
	});
});
