<script lang="ts">
	import { WEBUI_BASE_URL } from '$lib/constants';
	import { themeStaticBase } from '$lib/utils/themes';

	export let className = 'size-8';
	export let src = `${WEBUI_BASE_URL}/static/favicon.png`;

	$: defaultFavicon = `${$themeStaticBase}/favicon.png`;
	$: fallbackFavicon = `${WEBUI_BASE_URL}/static/favicon.png`;
</script>

<img
	aria-hidden="true"
	src={src === '' || src === fallbackFavicon
		? defaultFavicon
		: src.startsWith(WEBUI_BASE_URL) ||
			  src.startsWith('https://www.gravatar.com/avatar/') ||
			  src.startsWith('data:') ||
			  src.startsWith('/')
			? src
			: `${WEBUI_BASE_URL}/user.png`}
	class=" {className} object-cover rounded-full"
	alt="profile"
	draggable="false"
/>
