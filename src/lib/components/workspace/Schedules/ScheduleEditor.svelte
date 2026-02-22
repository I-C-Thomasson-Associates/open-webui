<script lang="ts">
	import { getContext, onMount } from 'svelte';

	const i18n = getContext('i18n');

	import { goto } from '$app/navigation';
	import { user, models, tools as toolsStore, functions as functionsStore } from '$lib/stores';
	import { getTools } from '$lib/apis/tools';
	import { getFunctions } from '$lib/apis/functions';

	import ChevronLeft from '$lib/components/icons/ChevronLeft.svelte';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import ToolsSelector from '$lib/components/workspace/Models/ToolsSelector.svelte';
	import FiltersSelector from '$lib/components/workspace/Models/FiltersSelector.svelte';

	let formElement = null;
	let loading = false;

	export let edit = false;
	export let onSave = (data: any) => {};

	export let id = '';
	export let name = '';
	export let description = '';
	export let model_id = '';
	export let prompt = '';
	export let selectedTools: string[] = [];
	export let selectedFilters: string[] = [];
	export let frequency = 'once';
	export let scheduled_at: number | null = null;
	export let is_active = true;

	let scheduledDate = '';
	let scheduledTime = '';
	let availableModels = [];

	let toolIds: string[] = [];
	let filterIds: string[] = [];

	$: availableModels = $models ?? [];

	onMount(async () => {
		const tools = await getTools(localStorage.token);
		toolsStore.set(tools ?? []);

		const funcs = await getFunctions(localStorage.token);
		functionsStore.set(funcs ?? []);

		toolIds = selectedTools ?? [];
		filterIds = selectedFilters ?? [];

		if (scheduled_at) {
			const date = new Date(scheduled_at * 1000);
			scheduledDate = date.toISOString().split('T')[0];
			scheduledTime = date.toTimeString().slice(0, 5);
		}
	});

	const getScheduledTimestamp = () => {
		if (scheduledDate && scheduledTime) {
			return Math.floor(new Date(`${scheduledDate}T${scheduledTime}`).getTime() / 1000);
		}
		return null;
	};
</script>

<div class="flex flex-col flex-auto overflow-y-auto h-full">
	<div class="flex items-center gap-1 px-1 mt-1">
		<Tooltip content={$i18n.t('Back')}>
			<button
				class="flex items-center p-1 rounded-xl bg-transparent hover:bg-gray-100 dark:hover:bg-gray-850 transition"
				on:click={() => {
					goto('/workspace/schedules');
				}}
			>
				<ChevronLeft strokeWidth="2.5" className="size-4" />
			</button>
		</Tooltip>

		<div class="text-lg font-medium self-center">
			{edit ? $i18n.t('Edit Schedule') : $i18n.t('Create Schedule')}
		</div>
	</div>

	<div class="flex-1 overflow-y-auto px-1 mt-4">
		<form
			bind:this={formElement}
			class="flex flex-col gap-4 max-w-2xl"
			on:submit|preventDefault={() => {
				loading = true;
				onSave({
					id,
					name,
					description,
					model_id,
					prompt,
					tools: toolIds,
					filters: filterIds,
					frequency,
					scheduled_at: getScheduledTimestamp(),
					is_active
				});
				loading = false;
			}}
		>
			<!-- Name -->
			<div>
				<label for="schedule-name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Name')} <span class="text-red-500">*</span>
				</label>
				<input
					id="schedule-name"
					class="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
					type="text"
					bind:value={name}
					placeholder={$i18n.t('Enter schedule name')}
					required
				/>
			</div>

			<!-- Description -->
			<div>
				<label for="schedule-description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Description')}
				</label>
				<input
					id="schedule-description"
					class="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
					type="text"
					bind:value={description}
					placeholder={$i18n.t('Enter description (optional)')}
				/>
			</div>

			<!-- Model -->
			<div>
				<label for="schedule-model" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Model')} <span class="text-red-500">*</span>
				</label>
				<select
					id="schedule-model"
					class="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
					bind:value={model_id}
					required
				>
					<option value="" disabled>{$i18n.t('Select a model')}</option>
					{#each availableModels as model}
						<option value={model.id}>{model.name ?? model.id}</option>
					{/each}
				</select>
			</div>

			<!-- Prompt -->
			<div>
				<label for="schedule-prompt" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Prompt')} <span class="text-red-500">*</span>
				</label>
				<textarea
					id="schedule-prompt"
					class="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600 min-h-[120px]"
					bind:value={prompt}
					placeholder={$i18n.t('Enter the task prompt')}
					required
					rows="5"
				/>
			</div>

			<!-- Tools (grouped checkboxes, same as model editor) -->
			<div>
				<ToolsSelector bind:selectedToolIds={toolIds} tools={$toolsStore ?? []} />
			</div>

			<!-- Filters (grouped checkboxes, same as model editor) -->
			<div>
				<FiltersSelector
					bind:selectedFilterIds={filterIds}
					filters={($functionsStore ?? []).filter((func) => func.type === 'filter')}
				/>
			</div>

			<!-- Frequency -->
			<div>
				<label for="schedule-frequency" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Frequency')} <span class="text-red-500">*</span>
				</label>
				<select
					id="schedule-frequency"
					class="w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
					bind:value={frequency}
				>
					<option value="once">{$i18n.t('Once')}</option>
					<option value="daily">{$i18n.t('Daily')}</option>
					<option value="weekly">{$i18n.t('Weekly')}</option>
					<option value="monthly">{$i18n.t('Monthly')}</option>
				</select>
			</div>

			<!-- Scheduled At -->
			<div>
				<label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
					{$i18n.t('Scheduled Time')}
				</label>
				<div class="flex gap-2">
					<input
						class="flex-1 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
						type="date"
						bind:value={scheduledDate}
					/>
					<input
						class="flex-1 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-850 px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-gray-300 dark:focus:ring-gray-600"
						type="time"
						bind:value={scheduledTime}
					/>
				</div>
			</div>

			<!-- Active Toggle -->
			<div class="flex items-center gap-2">
				<label class="relative inline-flex items-center cursor-pointer">
					<input type="checkbox" class="sr-only peer" bind:checked={is_active} />
					<div
						class="w-9 h-5 bg-gray-200 peer-focus:outline-none rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all dark:border-gray-600 peer-checked:bg-black dark:peer-checked:bg-white"
					></div>
				</label>
				<span class="text-sm font-medium text-gray-700 dark:text-gray-300">
					{$i18n.t('Active')}
				</span>
			</div>

			<!-- Submit -->
			<div class="flex justify-end pb-4">
				<button
					class="px-4 py-2 rounded-xl bg-black text-white dark:bg-white dark:text-black font-medium text-sm transition hover:opacity-90 disabled:opacity-50"
					type="submit"
					disabled={loading}
				>
					{edit ? $i18n.t('Save') : $i18n.t('Create')}
				</button>
			</div>
		</form>
	</div>
</div>
