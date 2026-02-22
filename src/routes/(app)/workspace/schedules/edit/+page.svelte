<script>
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { getScheduleById, getSchedules, updateScheduleById } from '$lib/apis/schedules';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import ScheduleEditor from '$lib/components/workspace/Schedules/ScheduleEditor.svelte';
	import { schedules } from '$lib/stores';
	import { onMount, getContext } from 'svelte';
	import { toast } from 'svelte-sonner';

	const i18n = getContext('i18n');

	let schedule = null;

	const saveHandler = async (data) => {
		const res = await updateScheduleById(localStorage.token, schedule.id, {
			name: data.name,
			description: data.description,
			model_id: data.model_id,
			prompt: data.prompt,
			tools: data.tools,
			filters: data.filters,
			frequency: data.frequency,
			scheduled_at: data.scheduled_at,
			is_active: data.is_active,
			meta: data.meta
		}).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (res) {
			toast.success($i18n.t('Schedule updated successfully'));
			schedules.set(await getSchedules(localStorage.token));
			await goto('/workspace/schedules');
		}
	};

	onMount(async () => {
		const id = $page.url.searchParams.get('id');

		if (id) {
			const res = await getScheduleById(localStorage.token, id).catch((error) => {
				toast.error(`${error}`);
				goto('/workspace/schedules');
				return null;
			});

			if (res) {
				schedule = res;
			}
		} else {
			goto('/workspace/schedules');
		}
	});
</script>

{#if schedule}
	<ScheduleEditor
		edit={true}
		id={schedule.id}
		name={schedule.name}
		description={schedule.description ?? ''}
		model_id={schedule.model_id}
		prompt={schedule.prompt}
		selectedTools={schedule.tools ?? []}
		selectedFilters={schedule.filters ?? []}
		selectedActions={schedule.meta?.actionIds ?? []}
		meta={schedule.meta ?? {}}
		frequency={schedule.frequency}
		scheduled_at={schedule.scheduled_at}
		is_active={schedule.is_active}
		onSave={(value) => {
			saveHandler(value);
		}}
	/>
{:else}
	<div class="flex items-center justify-center h-full">
		<div class=" pb-16">
			<Spinner className="size-5" />
		</div>
	</div>
{/if}
