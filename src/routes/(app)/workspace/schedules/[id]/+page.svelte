<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { goto } from '$app/navigation';
	import { onMount, getContext } from 'svelte';
	import { page } from '$app/stores';

	const i18n = getContext('i18n');

	import { getScheduleById, getScheduleRuns, getScheduleRunById } from '$lib/apis/schedules';
	import ScheduleRunsViewer from '$lib/components/workspace/Schedules/ScheduleRunsViewer.svelte';
	import Spinner from '$lib/components/common/Spinner.svelte';

	let schedule = null;
	let runs = [];

	$: scheduleId = $page.params.id;

	onMount(async () => {
		if (scheduleId) {
			const _schedule = await getScheduleById(localStorage.token, scheduleId).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (_schedule) {
				schedule = _schedule;
				runs =
					(await getScheduleRuns(localStorage.token, scheduleId).catch(() => [])) ?? [];
			} else {
				goto('/workspace/schedules');
			}
		} else {
			goto('/workspace/schedules');
		}
	});
</script>

{#if schedule}
	<ScheduleRunsViewer {schedule} {runs} />
{:else}
	<div class="flex items-center justify-center h-full">
		<div class="pb-16">
			<Spinner className="size-5" />
		</div>
	</div>
{/if}
