<script context="module" lang="ts">
	export type RealtimeEngine = 'openai' | 'azure' | 'openrouter';

	export type RealtimeSettings = {
		ENABLED?: boolean;
		ENGINE?: string;
		OPENAI_API_BASE_URL: string;
		OPENAI_API_KEY: string;
		MODEL: string;
		VOICE: string;
		TRANSCRIPTION_MODEL: string;
		REALTIME_CALL_PROMPT_TEMPLATE: string;
		[key: string]: unknown;
	};

	// Examples only: these are not enforced and do not claim availability. Azure has no
	// default base URL (it is resource specific); the placeholder is shown instead.
	export const REALTIME_PRESETS: Record<
		RealtimeEngine,
		{ base: string; model: string; voice: string; transcription: string }
	> = {
		openai: {
			base: 'https://api.openai.com/v1',
			model: 'gpt-realtime-2.1-mini',
			voice: 'marin',
			transcription: 'gpt-transcribe'
		},
		azure: { base: '', model: 'gpt-realtime', voice: 'alloy', transcription: 'whisper-1' },
		openrouter: {
			base: 'https://openrouter.ai/api/v1',
			model: 'openai/gpt-4o-audio-preview',
			voice: 'alloy',
			transcription: 'google/gemini-2.5-flash'
		}
	};

	export const normalizeEngine = (engine: unknown): RealtimeEngine =>
		engine === 'azure' || engine === 'openrouter' ? engine : 'openai';

	// Called only for an explicit user selection. Always clears the API key so a key for
	// one provider is never sent to another; other fields take the selected defaults.
	export const applyEngine = (settings: RealtimeSettings, engine: unknown): RealtimeSettings => {
		const key = normalizeEngine(engine);
		const preset = REALTIME_PRESETS[key];
		return {
			...settings,
			ENGINE: key,
			OPENAI_API_BASE_URL: preset.base,
			OPENAI_API_KEY: '',
			MODEL: preset.model,
			VOICE: preset.voice,
			TRANSCRIPTION_MODEL: preset.transcription
		};
	};
</script>

<script lang="ts">
	import { getContext } from 'svelte';
	import type { Writable } from 'svelte/store';
	import type { i18n as i18nType } from 'i18next';

	import SensitiveInput from '$lib/components/common/SensitiveInput.svelte';
	import SettingsSelect from '$lib/components/common/SettingsSelect.svelte';
	import Textarea from '$lib/components/common/Textarea.svelte';
	import AdminSettingField from '$lib/components/admin/Settings/AdminSettingField.svelte';

	const i18n = getContext<Writable<i18nType>>('i18n');

	export let realtime: RealtimeSettings;
	export let inputClass = '';
	export let textareaClass = '';

	// Display only; the stored value is not touched on render.
	$: engine = normalizeEngine(realtime.ENGINE);
	$: preset = REALTIME_PRESETS[engine];

	let selected = normalizeEngine(realtime.ENGINE);

	const onEngineChange = () => {
		realtime = applyEngine(realtime, selected);
	};

	$: baseLabel =
		engine === 'azure'
			? $i18n.t('Azure OpenAI base URL')
			: engine === 'openrouter'
				? $i18n.t('OpenRouter base URL')
				: $i18n.t('OpenAI API Base URL');
	$: modelLabel =
		engine === 'azure'
			? $i18n.t('Azure model deployment')
			: engine === 'openrouter'
				? $i18n.t('Audio output model')
				: $i18n.t('Voice Model');
	$: transcriptionLabel =
		engine === 'openrouter'
			? $i18n.t('Input audio chat model')
			: $i18n.t('Input Transcription Model');
</script>

<AdminSettingField label={$i18n.t('Realtime provider')} forId="realtime-provider">
	<SettingsSelect
		id="realtime-provider"
		bind:value={selected}
		ariaLabel={$i18n.t('Realtime provider')}
		on:change={onEngineChange}
	>
		<option value="openai">{$i18n.t('OpenAI Realtime')}</option>
		<option value="azure">{$i18n.t('Azure OpenAI Realtime')}</option>
		<option value="openrouter">{$i18n.t('OpenRouter (turn-based)')}</option>
	</SettingsSelect>
</AdminSettingField>

{#if engine === 'azure'}
	<p class="text-[0.6875rem] text-gray-400 dark:text-gray-600">
		{$i18n.t(
			'Uses the GA Azure OpenAI Realtime API with an API key (no Microsoft Entra or preview API). The model field is your deployment name, which must be a supported GA realtime model. Defaults are examples only.'
		)}
	</p>
{:else if engine === 'openrouter'}
	<p class="text-[0.6875rem] text-gray-400 dark:text-gray-600">
		{$i18n.t(
			'Turn-based, not native realtime: speech-to-text, then the selected chat model, then spoken audio. Latency is higher because the full response is buffered and must be WAV (24 kHz mono PCM16) for playback; it is not a native stream. There are no avatar gestures and no exact native barge-in. Voice calls still use authenticated chat delegation, and tool approval is unchanged. Example models are not enforced and do not imply availability.'
		)}
	</p>
{/if}

<div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
	<AdminSettingField label={baseLabel} forId="realtime-base-url">
		<input
			id="realtime-base-url"
			class={inputClass}
			bind:value={realtime.OPENAI_API_BASE_URL}
			placeholder={engine === 'azure' ? 'https://resource.openai.azure.com/openai/v1' : preset.base}
		/>
	</AdminSettingField>
	<AdminSettingField label={$i18n.t('API Key')}>
		<SensitiveInput
			variant="settings"
			placeholder={$i18n.t('API Key')}
			bind:value={realtime.OPENAI_API_KEY}
		/>
	</AdminSettingField>
</div>
<div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
	<AdminSettingField label={modelLabel} forId="realtime-model">
		<input
			id="realtime-model"
			class={inputClass}
			bind:value={realtime.MODEL}
			placeholder={preset.model}
		/>
	</AdminSettingField>
	<AdminSettingField label={$i18n.t('Voice')} forId="realtime-voice">
		<input
			id="realtime-voice"
			class={inputClass}
			bind:value={realtime.VOICE}
			placeholder={preset.voice}
		/>
	</AdminSettingField>
</div>
<AdminSettingField label={transcriptionLabel} forId="realtime-transcription-model">
	<input
		id="realtime-transcription-model"
		class={inputClass}
		bind:value={realtime.TRANSCRIPTION_MODEL}
		placeholder={preset.transcription}
	/>
</AdminSettingField>
<AdminSettingField
	label={$i18n.t('Prompt Template')}
	description={engine === 'openrouter'
		? $i18n.t(
				'OpenRouter ignores the Realtime prompt template because every request uses the selected chat model.'
			)
		: ''}
>
	<Textarea
		className={textareaClass}
		bind:value={realtime.REALTIME_CALL_PROMPT_TEMPLATE}
		placeholder={$i18n.t('Leave empty to use the default prompt, or enter a custom prompt')}
	/>
</AdminSettingField>
