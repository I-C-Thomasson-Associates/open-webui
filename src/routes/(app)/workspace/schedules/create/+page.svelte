<script>
	import { goto } from '$app/navigation';
	import { createNewSchedule, getSchedules } from '$lib/apis/schedules';
	import ScheduleEditor from '$lib/components/workspace/Schedules/ScheduleEditor.svelte';
	import { schedules } from '$lib/stores';
	import { onMount, getContext } from 'svelte';
	import { toast } from 'svelte-sonner';

	const i18n = getContext('i18n');
	let mounted = false;

	const saveHandler = async (data) => {
		const res = await createNewSchedule(localStorage.token, {
			name: data.name,
			description: data.description,
			model_id: data.model_id,
			prompt: data.prompt,
			tools: data.tools,
			filters: data.filters,
			frequency: data.frequency,
			scheduled_at: data.scheduled_at,
			is_active: data.is_active,
			meta: data.meta,
			access_grants: data.access_grants
		}).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (res) {
			toast.success($i18n.t('Schedule created successfully'));
			schedules.set(await getSchedules(localStorage.token));
			await goto('/workspace/schedules');
		}
	};

	onMount(() => {
		mounted = true;
	});
</script>

{#if mounted}
	<ScheduleEditor
		onSave={(value) => {
			saveHandler(value);
		}}
	/>
{/if}
