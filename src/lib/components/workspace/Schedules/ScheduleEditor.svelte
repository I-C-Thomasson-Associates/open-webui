<script lang="ts">
	import { getContext, onMount } from 'svelte';

	const i18n = getContext('i18n');

	import { goto } from '$app/navigation';
	import { user, models, tools as toolsStore, functions as functionsStore } from '$lib/stores';
	import { getTools } from '$lib/apis/tools';
	import { getFunctions } from '$lib/apis/functions';

	import ChevronLeft from '$lib/components/icons/ChevronLeft.svelte';
	import LockClosed from '$lib/components/icons/LockClosed.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import Switch from '$lib/components/common/Switch.svelte';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import Textarea from '$lib/components/common/Textarea.svelte';
	import AccessControlModal from '$lib/components/workspace/common/AccessControlModal.svelte';
	import ToolsSelector from '$lib/components/workspace/Models/ToolsSelector.svelte';
	import FiltersSelector from '$lib/components/workspace/Models/FiltersSelector.svelte';
	import ActionsSelector from '$lib/components/workspace/Models/ActionsSelector.svelte';
	import Capabilities from '$lib/components/workspace/Models/Capabilities.svelte';
	import BuiltinTools from '$lib/components/workspace/Models/BuiltinTools.svelte';
	import Knowledge from '$lib/components/workspace/Models/Knowledge.svelte';
	import { toast } from 'svelte-sonner';

	let formElement = null;
	let loading = false;
	let showAccessControlModal = false;

	export let edit = false;
	export let onSave = (data: any) => {};

	export let id = '';
	export let name = '';
	export let description = '';
	export let model_id = '';
	export let prompt = '';
	export let selectedTools: string[] = [];
	export let selectedFilters: string[] = [];
	export let selectedActions: string[] = [];
	export let frequency = 'once';
	export let scheduled_at: number | null = null;
	export let is_active = true;
	export let meta: Record<string, any> = {};
	export let accessGrants: any[] = [];

	let scheduledDate = '';
	let scheduledTime = '';
	let availableModels = [];

	let toolIds: string[] = [];
	let filterIds: string[] = [];
	let actionIds: string[] = [];
	let capabilities: Record<string, boolean> = {};
	let builtinTools: Record<string, boolean> = {};
	let knowledge: any[] = [];

	$: availableModels = $models ?? [];

	onMount(async () => {
		const tools = await getTools(localStorage.token);
		toolsStore.set(tools ?? []);

		const funcs = await getFunctions(localStorage.token);
		functionsStore.set(funcs ?? []);

		toolIds = selectedTools ?? [];
		filterIds = selectedFilters ?? [];
		actionIds = selectedActions ?? [];
		capabilities = meta?.capabilities ?? {};
		builtinTools = meta?.builtinTools ?? {};
		knowledge = meta?.knowledge ?? [];

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

<AccessControlModal
	bind:show={showAccessControlModal}
	bind:accessGrants
	accessRoles={['read']}
	share={$user?.permissions?.sharing?.models || $user?.role === 'admin'}
	sharePublic={$user?.role === 'admin'}
/>

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

	<div class="w-full max-h-full flex justify-center">
		<form
			bind:this={formElement}
			class="flex flex-col w-full px-1"
			on:submit|preventDefault={() => {
				loading = true;
				if (knowledge.some((item) => item.status === 'uploading')) {
					toast.error($i18n.t('Please wait until all files are uploaded.'));
					loading = false;
					return;
				}
				const metaData = {
					...meta,
					capabilities,
					builtinTools,
					actionIds
				};
				if (knowledge.length > 0) {
					metaData.knowledge = knowledge;
				} else {
					delete metaData.knowledge;
				}
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
					is_active,
					meta: metaData,
					access_grants: accessGrants
				});
				loading = false;
			}}
		>
			<div class="w-full px-1">
				<div class="flex flex-col w-full flex-1">
					<div class="flex justify-between items-start my-2">
						<div class="flex flex-col w-full">
							<div class="flex-1 w-full">
								<input
									class="text-3xl w-full bg-transparent outline-hidden"
									placeholder={$i18n.t('Schedule Name')}
									bind:value={name}
									required
								/>
							</div>
						</div>

						<div class="shrink-0">
							<button
								class="bg-gray-50 shrink-0 hover:bg-gray-100 text-black dark:bg-gray-850 dark:hover:bg-gray-800 dark:text-white transition px-2 py-1 rounded-full flex gap-1 items-center"
								type="button"
								on:click={() => {
									showAccessControlModal = true;
								}}
							>
								<LockClosed strokeWidth="2.5" className="size-3.5 shrink-0" />

								<div class="text-sm font-medium shrink-0">
									{$i18n.t('Access')}
								</div>
							</button>
						</div>
					</div>

					<div class="mb-1">
						<div class="mb-1 flex w-full justify-between items-center">
							<div class="self-center text-xs font-medium text-gray-500">
								{$i18n.t('Description')}
							</div>
						</div>

						<Textarea
							className="text-sm w-full bg-transparent outline-hidden resize-none overflow-y-hidden"
							placeholder={$i18n.t('Add a short description about what this schedule does')}
							bind:value={description}
						/>
					</div>
				</div>

				<div class="my-2">
					<div class="mb-1">
						<div class="text-xs font-medium text-gray-500">
							{$i18n.t('Base Model')}
						</div>
					</div>

					<div>
						<select
							class="dark:bg-gray-900 text-sm w-full bg-transparent outline-hidden"
							placeholder={$i18n.t('Select a model')}
							bind:value={model_id}
							required
						>
							<option value="" class="text-gray-900">{$i18n.t('Select a model')}</option>
							{#each availableModels as model}
								<option value={model.id} class="text-gray-900">{model.name ?? model.id}</option>
							{/each}
						</select>
					</div>
				</div>

				<div class="my-2">
					<div class="my-1">
						<div class="text-xs font-medium mb-2">{$i18n.t('Task Prompt')}</div>
						<div>
							<Textarea
								className="text-sm w-full bg-transparent outline-hidden resize-none overflow-y-hidden"
								placeholder={$i18n.t(
									'Write your task prompt here\ne.g.) Generate a daily summary report of the latest news in AI.'
								)}
								rows={4}
								bind:value={prompt}
								required
							/>
						</div>
					</div>
				</div>

				<hr class="border-gray-100/30 dark:border-gray-850/30 my-2" />

				<div class="my-2">
					<div class="flex w-full justify-between">
						<div class="self-center text-xs font-medium text-gray-500">
							{$i18n.t('Schedule Settings')}
						</div>
					</div>

					<div class="mt-2">
						<div class="my-1">
							<div class="text-xs font-medium mb-2">{$i18n.t('Frequency')}</div>
							<select
								class="dark:bg-gray-900 text-sm w-full bg-transparent outline-hidden"
								bind:value={frequency}
							>
								<option value="once">{$i18n.t('Once')}</option>
								<option value="daily">{$i18n.t('Daily')}</option>
								<option value="weekly">{$i18n.t('Weekly')}</option>
								<option value="monthly">{$i18n.t('Monthly')}</option>
							</select>
						</div>

						<div class="my-1 mt-3">
							<div class="text-xs font-medium mb-2">{$i18n.t('Scheduled Time')}</div>
							<div class="flex gap-2">
								<input
									class="flex-1 dark:bg-gray-900 text-sm bg-transparent outline-hidden"
									type="date"
									bind:value={scheduledDate}
								/>
								<input
									class="flex-1 dark:bg-gray-900 text-sm bg-transparent outline-hidden"
									type="time"
									bind:value={scheduledTime}
								/>
							</div>
						</div>

						<div class="my-1 mt-3 flex items-center justify-between">
							<div id="active-label" class="text-xs font-medium">
								{$i18n.t('Active')}
							</div>
							<Switch
								tooltip={true}
								ariaLabelledbyId="active-label"
								bind:state={is_active}
							/>
						</div>
					</div>
				</div>

				<hr class="border-gray-100/30 dark:border-gray-850/30 my-2" />

				<div class="my-4">
					<ToolsSelector bind:selectedToolIds={toolIds} tools={$toolsStore ?? []} />
				</div>

				{#if ($functionsStore ?? []).filter((func) => func.type === 'filter').length > 0 || ($functionsStore ?? []).filter((func) => func.type === 'action').length > 0}
					<hr class="border-gray-100/30 dark:border-gray-850/30 my-4" />

					{#if ($functionsStore ?? []).filter((func) => func.type === 'filter').length > 0}
						<div class="my-4">
							<FiltersSelector
								bind:selectedFilterIds={filterIds}
								filters={($functionsStore ?? []).filter((func) => func.type === 'filter')}
							/>
						</div>
					{/if}

					{#if ($functionsStore ?? []).filter((func) => func.type === 'action').length > 0}
						<div class="my-4">
							<ActionsSelector
								bind:selectedActionIds={actionIds}
								actions={($functionsStore ?? []).filter((func) => func.type === 'action')}
							/>
						</div>
					{/if}
				{/if}

				<hr class="border-gray-100/30 dark:border-gray-850/30 my-4" />

				<div class="my-4">
					<Capabilities bind:capabilities />
				</div>

				{#if capabilities.builtin_tools}
					<div class="my-4">
						<BuiltinTools bind:builtinTools />
					</div>
				{/if}

				<hr class="border-gray-100/30 dark:border-gray-850/30 my-4" />

				<div class="my-4">
					<Knowledge bind:selectedItems={knowledge} />
				</div>

				<hr class="border-gray-100/30 dark:border-gray-850/30 my-4" />

				<div class="my-2 flex justify-end">
					<button
						class="text-sm px-3 py-2 transition rounded-lg {loading
							? 'cursor-not-allowed bg-black hover:bg-gray-900 text-white dark:bg-white dark:hover:bg-gray-100 dark:text-black'
							: 'bg-black hover:bg-gray-900 text-white dark:bg-white dark:hover:bg-gray-100 dark:text-black'} flex w-full justify-center"
						type="submit"
						disabled={loading}
					>
						<div class="self-center font-medium">
							{#if edit}
								{$i18n.t('Save & Update')}
							{:else}
								{$i18n.t('Save & Create')}
							{/if}
						</div>

						{#if loading}
							<div class="ml-1.5 self-center">
								<Spinner />
							</div>
						{/if}
					</button>
				</div>
			</div>
		</form>
	</div>
</div>
