<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { onMount, getContext, tick, onDestroy } from 'svelte';
	const i18n = getContext('i18n');

	import { WEBUI_NAME, user, models, tools as _tools, schedules as _schedules } from '$lib/stores';

	import { goto } from '$app/navigation';
	import {
		getSchedules,
		deleteScheduleById,
		runScheduleById,
		getScheduleRuns,
		getScheduleRunById
	} from '$lib/apis/schedules';
	import { capitalizeFirstLetter } from '$lib/utils';

	import Tooltip from '../common/Tooltip.svelte';
	import ScheduleMenu from './Schedules/ScheduleMenu.svelte';
	import ScheduleRunModal from './Schedules/ScheduleRunModal.svelte';
	import EllipsisHorizontal from '../icons/EllipsisHorizontal.svelte';
	import DeleteConfirmDialog from '$lib/components/common/ConfirmDialog.svelte';
	import GarbageBin from '../icons/GarbageBin.svelte';
	import Search from '../icons/Search.svelte';
	import Plus from '../icons/Plus.svelte';
	import Spinner from '../common/Spinner.svelte';
	import XMark from '../icons/XMark.svelte';

	let shiftKey = false;
	let loaded = false;

	let query = '';
	let searchDebounceTimer: ReturnType<typeof setTimeout>;

	let showDeleteConfirm = false;
	let selectedSchedule = null;

	let showRunModal = false;
	let selectedRun = null;

	let schedules = [];
	let filteredItems = [];
	let scheduleRuns = {};

	$: if (query !== undefined) {
		clearTimeout(searchDebounceTimer);
		searchDebounceTimer = setTimeout(() => {
			setFilteredItems();
		}, 300);
	}

	$: if (schedules) {
		setFilteredItems();
	}

	const setFilteredItems = () => {
		filteredItems = schedules.filter((s) => {
			if (query === '') return true;
			const lowerQuery = query.toLowerCase();
			return (
				(s.name || '').toLowerCase().includes(lowerQuery) ||
				(s.description || '').toLowerCase().includes(lowerQuery) ||
				(s.model_id || '').toLowerCase().includes(lowerQuery) ||
				(s.user?.name || '').toLowerCase().includes(lowerQuery) ||
				(s.user?.email || '').toLowerCase().includes(lowerQuery)
			);
		});
	};

	const deleteHandler = async (schedule) => {
		const res = await deleteScheduleById(localStorage.token, schedule.id).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (res) {
			toast.success($i18n.t('Schedule deleted successfully'));
			await init();
		}
	};

	const runHandler = async (schedule) => {
		const run = await runScheduleById(localStorage.token, schedule.id).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (run) {
			toast.success($i18n.t('Schedule executed successfully'));
			// Refresh runs for this schedule
			scheduleRuns[schedule.id] = await getScheduleRuns(localStorage.token, schedule.id);
			selectedRun = run;
			showRunModal = true;
		}
	};

	const viewRunHandler = async (run) => {
		const fullRun = await getScheduleRunById(localStorage.token, run.id).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (fullRun) {
			selectedRun = fullRun;
			showRunModal = true;
		}
	};

	const loadRuns = async (scheduleId) => {
		if (!scheduleRuns[scheduleId]) {
			scheduleRuns[scheduleId] = await getScheduleRuns(localStorage.token, scheduleId).catch(
				() => []
			);
		}
		return scheduleRuns[scheduleId] || [];
	};

	const formatDate = (timestamp) => {
		if (!timestamp) return 'N/A';
		return new Date(timestamp * 1000).toLocaleString();
	};

	const init = async () => {
		schedules = (await getSchedules(localStorage.token)) ?? [];
		_schedules.set(schedules);

		// Load runs for each schedule
		for (const schedule of schedules) {
			scheduleRuns[schedule.id] = await getScheduleRuns(
				localStorage.token,
				schedule.id
			).catch(() => []);
		}
	};

	onMount(async () => {
		await init();
		loaded = true;

		const onKeyDown = (event) => {
			if (event.key === 'Shift') {
				shiftKey = true;
			}
		};

		const onKeyUp = (event) => {
			if (event.key === 'Shift') {
				shiftKey = false;
			}
		};

		const onBlur = () => {
			shiftKey = false;
		};

		window.addEventListener('keydown', onKeyDown);
		window.addEventListener('keyup', onKeyUp);
		window.addEventListener('blur-sm', onBlur);

		return () => {
			clearTimeout(searchDebounceTimer);
			window.removeEventListener('keydown', onKeyDown);
			window.removeEventListener('keyup', onKeyUp);
			window.removeEventListener('blur-sm', onBlur);
		};
	});

	onDestroy(() => {
		clearTimeout(searchDebounceTimer);
	});
</script>

<svelte:head>
	<title>
		{$i18n.t('Schedules')} • {$WEBUI_NAME}
	</title>
</svelte:head>

{#if loaded}
	<div class="flex flex-col gap-1 px-1 mt-1.5 mb-3">
		<div class="flex justify-between items-center">
			<div class="flex items-center md:self-center text-xl font-medium px-0.5 gap-2 shrink-0">
				<div>
					{$i18n.t('Schedules')}
				</div>

				<div class="text-lg font-medium text-gray-500 dark:text-gray-500">
					{filteredItems.length}
				</div>
			</div>

			<div class="flex w-full justify-end gap-1.5">
				<a
					class=" px-2 py-1.5 rounded-xl bg-black text-white dark:bg-white dark:text-black transition font-medium text-sm flex items-center"
					href="/workspace/schedules/create"
				>
					<Plus className="size-3" strokeWidth="2.5" />

					<div class=" hidden md:block md:ml-1 text-xs">{$i18n.t('New Schedule')}</div>
				</a>
			</div>
		</div>
	</div>

	<div
		class="py-2 bg-white dark:bg-gray-900 rounded-3xl border border-gray-100/30 dark:border-gray-850/30"
	>
		<div class=" flex w-full space-x-2 py-0.5 px-3.5 pb-2">
			<div class="flex flex-1">
				<div class=" self-center ml-1 mr-3">
					<Search className="size-3.5" />
				</div>
				<input
					class=" w-full text-sm pr-4 py-1 rounded-r-xl outline-hidden bg-transparent"
					bind:value={query}
					placeholder={$i18n.t('Search Schedules')}
				/>
				{#if query}
					<div class="self-center pl-1.5 translate-y-[0.5px] rounded-l-xl bg-transparent">
						<button
							class="p-0.5 rounded-full hover:bg-gray-100 dark:hover:bg-gray-900 transition"
							on:click={() => {
								query = '';
							}}
						>
							<XMark className="size-3" strokeWidth="2" />
						</button>
					</div>
				{/if}
			</div>
		</div>

		{#if (filteredItems ?? []).length !== 0}
			<div class=" my-2 gap-2 grid px-3 lg:grid-cols-2">
				{#each filteredItems as schedule}
					<div
						class=" flex flex-col text-left w-full px-3 py-2.5 transition rounded-2xl cursor-pointer dark:hover:bg-gray-850/50 hover:bg-gray-50"
					>
						<div class="flex w-full">
							<a
								class=" flex flex-1 space-x-3.5 cursor-pointer w-full"
								href={`/workspace/schedules/edit?id=${encodeURIComponent(schedule.id)}`}
							>
								<div class="flex items-center text-left">
									<div class=" flex-1 self-center">
										<div class="flex items-center gap-2">
											<div class="line-clamp-1 text-sm font-medium">
												{schedule.name}
											</div>
											<span
												class="inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-medium {schedule.is_active
													? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
													: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'}"
											>
												{schedule.is_active ? $i18n.t('Active') : $i18n.t('Inactive')}
											</span>
										</div>
										<div class="px-0.5 mt-0.5">
											<div class="text-xs text-gray-500 shrink-0 line-clamp-1">
												{schedule.model_id} • {schedule.frequency}
												{#if schedule.user}
													• {$i18n.t('By {{name}}', {
														name: capitalizeFirstLetter(
															schedule?.user?.name ??
																schedule?.user?.email ??
																$i18n.t('Deleted User')
														)
													})}
												{/if}
											</div>
										</div>
									</div>
								</div>
							</a>

							<div class="flex flex-row gap-0.5 self-center">
								{#if shiftKey}
									<Tooltip content={$i18n.t('Delete')}>
										<button
											class="self-center w-fit text-sm px-2 py-2 dark:text-gray-300 dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5 rounded-xl"
											type="button"
											on:click={() => {
												deleteHandler(schedule);
											}}
										>
											<GarbageBin />
										</button>
									</Tooltip>
								{:else}
									<ScheduleMenu
										editHandler={() => {
											goto(
												`/workspace/schedules/edit?id=${encodeURIComponent(schedule.id)}`
											);
										}}
										runHandler={() => {
											runHandler(schedule);
										}}
										deleteHandler={async () => {
											selectedSchedule = schedule;
											showDeleteConfirm = true;
										}}
										onClose={() => {}}
									>
										<button
											class="self-center w-fit text-sm p-1.5 dark:text-gray-300 dark:hover:text-white hover:bg-black/5 dark:hover:bg-white/5 rounded-xl"
											type="button"
										>
											<EllipsisHorizontal className="size-5" />
										</button>
									</ScheduleMenu>
								{/if}
							</div>
						</div>

						<!-- Recent Runs -->
						{#if scheduleRuns[schedule.id]?.length > 0}
							<div class="mt-2 pl-1">
								<div class="text-xs text-gray-400 dark:text-gray-500 mb-1">
									{$i18n.t('Recent Runs')}:
								</div>
								<div class="flex flex-wrap gap-1">
									{#each scheduleRuns[schedule.id].slice(0, 3) as run}
										<button
											class="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-xs transition {run.status ===
											'completed'
												? 'bg-green-50 text-green-700 hover:bg-green-100 dark:bg-green-900/30 dark:text-green-300 dark:hover:bg-green-900/50'
												: run.status === 'failed'
													? 'bg-red-50 text-red-700 hover:bg-red-100 dark:bg-red-900/30 dark:text-red-300 dark:hover:bg-red-900/50'
													: 'bg-gray-50 text-gray-600 hover:bg-gray-100 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700'}"
											on:click|stopPropagation={() => {
												viewRunHandler(run);
											}}
										>
											<span
												class="w-1.5 h-1.5 rounded-full {run.status === 'completed'
													? 'bg-green-500'
													: run.status === 'failed'
														? 'bg-red-500'
														: 'bg-gray-400'}"
											></span>
											{formatDate(run.created_at)}
										</button>
									{/each}
								</div>
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{:else}
			<div class=" w-full h-full flex flex-col justify-center items-center my-16 mb-24">
				<div class="max-w-md text-center">
					<div class=" text-3xl mb-3">📅</div>
					<div class=" text-lg font-medium mb-1">{$i18n.t('No schedules found')}</div>
					<div class=" text-gray-500 text-center text-xs">
						{$i18n.t('Create a schedule to run tasks automatically at specified times.')}
					</div>
				</div>
			</div>
		{/if}
	</div>

	<ScheduleRunModal bind:show={showRunModal} run={selectedRun} />

	<DeleteConfirmDialog
		bind:show={showDeleteConfirm}
		title={$i18n.t('Delete schedule?')}
		on:confirm={() => {
			deleteHandler(selectedSchedule);
		}}
	>
		<div class=" text-sm text-gray-500 truncate">
			{$i18n.t('This will delete')}
			<span class="font-medium">{selectedSchedule?.name}</span>.
		</div>
	</DeleteConfirmDialog>
{:else}
	<div class="w-full h-full flex justify-center items-center">
		<Spinner className="size-5" />
	</div>
{/if}
