<script lang="ts">
	import { getContext, onDestroy, onMount } from 'svelte';
	import { toast } from 'svelte-sonner';

	import { config, settings } from '$lib/stores';
	import { transcribeAudio } from '$lib/apis/audio';

	import XMark from '$lib/components/icons/XMark.svelte';

	const i18n: any = getContext('i18n');

	export let chunkDurationMs = 5 * 60 * 1000;
	export let onCancel = () => {};
	export let onConfirm = (data: { file: File; text: string; errors: string[] }) => {};

	type CaptureStatus = 'idle' | 'starting' | 'recording' | 'stopping' | 'transcribing';

	let status: CaptureStatus = 'idle';
	let displayStream: MediaStream | null = null;
	let micStream: MediaStream | null = null;
	let mixedStream: MediaStream | null = null;
	let audioContext: AudioContext | null = null;
	let mediaRecorder: MediaRecorder | null = null;

	let durationSeconds = 0;
	let durationCounter: ReturnType<typeof setInterval> | null = null;
	let chunkTimer: ReturnType<typeof setTimeout> | null = null;

	let chunkIndex = 0;
	let activeChunkParts: Blob[] = [];
	let transcriptChunks: string[] = [];
	let transcriptionErrors: string[] = [];
	let pendingTranscriptions = 0;
	let transcribedChunks = 0;
	let failedChunks = 0;
	let retryingTranscriptions = 0;
	let transcriptionChain = Promise.resolve();
	let currentRecorderStopped = Promise.resolve();
	let resolveCurrentRecorderStopped: (() => void) | null = null;

	let recordingActive = false;
	let stopping = false;
	let cancelled = false;
	let completed = false;
	let sourceEnded = false;
	let wakeLock: any = null;

	const mimeTypes = [
		'audio/webm; codecs=opus',
		'audio/webm',
		'audio/ogg; codecs=opus',
		'audio/mp4',
		'audio/wav'
	];
	const transcriptionRetryDelaysMs = [2000, 6000, 15000];

	const formatSeconds = (seconds: number) => {
		const minutes = Math.floor(seconds / 60);
		const remainingSeconds = seconds % 60;
		const formattedSeconds = remainingSeconds < 10 ? `0${remainingSeconds}` : remainingSeconds;
		return `${minutes}:${formattedSeconds}`;
	};

	const formatFilenameDate = () => {
		const date = new Date();
		const pad = (value: number) => String(value).padStart(2, '0');

		return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(
			date.getHours()
		)}-${pad(date.getMinutes())}`;
	};

	const getExtension = (type: string) => {
		const extension = type.split('/')[1]?.split(';')[0];
		return extension || 'webm';
	};

	const formatChunkRange = (index: number) => {
		const startSeconds = Math.floor((index * chunkDurationMs) / 1000);
		const endSeconds = Math.floor(((index + 1) * chunkDurationMs) / 1000);

		return `[${formatSeconds(startSeconds)}-${formatSeconds(endSeconds)}]`;
	};

	const clearChunkTimer = () => {
		if (chunkTimer) {
			clearTimeout(chunkTimer);
			chunkTimer = null;
		}
	};

	const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

	const transcribeChunkWithRetry = async (file: File) => {
		let lastError;

		for (let attempt = 0; attempt <= transcriptionRetryDelaysMs.length; attempt++) {
			if (cancelled) {
				break;
			}

			try {
				return await transcribeAudio(localStorage.token, file, $settings?.audio?.stt?.language, {
					diarize: true
				});
			} catch (error) {
				lastError = error;

				if (attempt >= transcriptionRetryDelaysMs.length || cancelled) {
					break;
				}

				retryingTranscriptions += 1;
				await sleep(transcriptionRetryDelaysMs[attempt]);
				retryingTranscriptions = Math.max(0, retryingTranscriptions - 1);
			}
		}

		throw lastError;
	};

	const startDurationCounter = () => {
		if (durationCounter) {
			clearInterval(durationCounter);
		}

		durationCounter = setInterval(() => {
			durationSeconds += 1;
		}, 1000);
	};

	const stopDurationCounter = () => {
		if (durationCounter) {
			clearInterval(durationCounter);
			durationCounter = null;
		}
	};

	const stopTracks = (stream: MediaStream | null) => {
		stream?.getTracks().forEach((track) => track.stop());
	};

	const hasLiveAudioTracks = (stream: MediaStream | null) =>
		stream?.getAudioTracks().some((track) => track.readyState === 'live') ?? false;

	const getErrorMessage = (error: unknown) => {
		if (error instanceof Error) {
			return error.message;
		}

		return `${error}`;
	};

	const requestWakeLock = async () => {
		if ('wakeLock' in navigator) {
			try {
				wakeLock = await (navigator as any).wakeLock.request('screen');
			} catch (error) {
				console.debug('Wake Lock request failed:', error);
			}
		}
	};

	const releaseWakeLock = async () => {
		if (!wakeLock) {
			return;
		}

		try {
			await wakeLock.release();
		} catch (error) {
			console.debug('Wake Lock release failed:', error);
		}

		wakeLock = null;
	};

	const cleanup = async () => {
		clearChunkTimer();
		stopDurationCounter();
		await releaseWakeLock();

		stopTracks(displayStream);
		stopTracks(micStream);
		stopTracks(mixedStream);

		displayStream = null;
		micStream = null;
		mixedStream = null;

		if (audioContext) {
			await audioContext.close().catch(() => {});
			audioContext = null;
		}
	};

	const enqueueTranscription = (blob: Blob, index: number, mimeType: string) => {
		pendingTranscriptions += 1;
		const ext = getExtension(mimeType);
		const file = new File([blob], `meeting-audio-${index + 1}.${ext}`, { type: mimeType });

		transcriptionChain = transcriptionChain.then(async () => {
			if (cancelled) {
				pendingTranscriptions -= 1;
				return;
			}

			try {
				const res = await transcribeChunkWithRetry(file);

				if (!cancelled) {
					transcriptChunks[index] = res?.text ? `${formatChunkRange(index)}\n${res.text}` : '';
					transcriptChunks = transcriptChunks;
					transcribedChunks += 1;
				}
			} catch (error) {
				console.error('Error transcribing meeting audio chunk:', error);
				if (!cancelled) {
					failedChunks += 1;
					transcriptionErrors = [
						...transcriptionErrors,
						$i18n.t('Chunk {{number}} failed to transcribe.', { number: index + 1 })
					];
				}
			} finally {
				pendingTranscriptions -= 1;
			}
		});
	};

	const startRecorderChunk = () => {
		if (!mixedStream || !recordingActive || stopping || cancelled) {
			return;
		}

		activeChunkParts = [];
		const mimeType = mimeTypes.find((type) => MediaRecorder.isTypeSupported(type));
		const recorderOptions = mimeType ? { mimeType } : undefined;
		const recorder = new MediaRecorder(mixedStream, recorderOptions);
		const currentChunkIndex = chunkIndex;
		chunkIndex += 1;

		currentRecorderStopped = new Promise((resolve) => {
			resolveCurrentRecorderStopped = resolve;
		});

		recorder.ondataavailable = (event) => {
			if (event.data.size > 0) {
				activeChunkParts.push(event.data);
			}
		};

		recorder.onstop = () => {
			clearChunkTimer();

			const recordedMimeType = recorder.mimeType || activeChunkParts[0]?.type || 'audio/webm';
			if (!cancelled && activeChunkParts.length > 0) {
				const blob = new Blob(activeChunkParts, { type: recordedMimeType });
				enqueueTranscription(blob, currentChunkIndex, recordedMimeType);
			}

			activeChunkParts = [];
			resolveCurrentRecorderStopped?.();
			resolveCurrentRecorderStopped = null;

			if (recordingActive && !stopping && !cancelled && !sourceEnded) {
				startRecorderChunk();
			}
		};

		mediaRecorder = recorder;
		recorder.start();

		chunkTimer = setTimeout(() => {
			if (recorder.state === 'recording') {
				recorder.stop();
			}
		}, chunkDurationMs);
	};

	const handleSourceEnded = async () => {
		if (!recordingActive || stopping || cancelled) {
			return;
		}

		if (hasLiveAudioTracks(displayStream) || hasLiveAudioTracks(micStream)) {
			return;
		}

		sourceEnded = true;
		toast.warning($i18n.t('Audio capture ended. Finalizing transcript.'));
		await stopCapture();
	};

	const handleVisibilityChange = async () => {
		if (recordingActive && document.visibilityState === 'visible') {
			await requestWakeLock();
		}
	};

	const startCapture = async () => {
		if (
			($config as any)?.audio?.stt?.engine === 'web' ||
			($settings?.audio?.stt?.engine ?? '') === 'web'
		) {
			toast.error($i18n.t('Capture Audio requires a server-side speech-to-text engine.'));
			return;
		}

		status = 'starting';
		cancelled = false;
		completed = false;
		stopping = false;
		sourceEnded = false;
		chunkIndex = 0;
		transcriptChunks = [];
		transcriptionErrors = [];
		pendingTranscriptions = 0;
		transcribedChunks = 0;
		failedChunks = 0;
		retryingTranscriptions = 0;
		transcriptionChain = Promise.resolve();
		durationSeconds = 0;
		let displayError: unknown = null;
		let micError: unknown = null;

		try {
			const displayOptions: DisplayMediaStreamOptions & {
				systemAudio?: 'include' | 'exclude';
				windowAudio?: 'exclude' | 'window' | 'system';
				surfaceSwitching?: 'include' | 'exclude';
			} = {
				video: true,
				audio: true,
				systemAudio: 'include',
				windowAudio: 'window',
				surfaceSwitching: 'include'
			};

			try {
				displayStream = await navigator.mediaDevices.getDisplayMedia(displayOptions);
			} catch (error) {
				displayError = error;
				displayStream = null;
			}

			if (displayStream && displayStream.getAudioTracks().length === 0) {
				displayError = new Error(
					$i18n.t('No shared audio was provided. Make sure audio sharing is enabled in the picker.')
				);
				stopTracks(displayStream);
				displayStream = null;
			}

			try {
				micStream = await navigator.mediaDevices.getUserMedia({
					audio: {
						echoCancellation: true,
						noiseSuppression: true,
						autoGainControl: true
					}
				});
			} catch (error) {
				micError = error;
				micStream = null;
			}

			const hasDisplayAudio = hasLiveAudioTracks(displayStream);
			const hasMicAudio = hasLiveAudioTracks(micStream);

			if (!hasDisplayAudio && !hasMicAudio) {
				throw new Error(
					$i18n.t('No audio source was allowed. Share meeting audio or allow microphone.')
				);
			}

			if (!hasDisplayAudio && hasMicAudio) {
				toast.warning($i18n.t('Shared audio was blocked. Continuing with microphone only.'));
			} else if (hasDisplayAudio && !hasMicAudio) {
				toast.warning($i18n.t('Microphone was blocked. Continuing with shared audio only.'));
			}

			audioContext = new AudioContext();
			const destination = audioContext.createMediaStreamDestination();
			const monoMixer = audioContext.createGain();
			monoMixer.channelCount = 1;
			monoMixer.channelCountMode = 'explicit';
			monoMixer.channelInterpretation = 'speakers';

			if (hasDisplayAudio && displayStream) {
				const displaySource = audioContext.createMediaStreamSource(
					new MediaStream(displayStream.getAudioTracks())
				);
				displaySource.connect(monoMixer);
			}

			if (hasMicAudio && micStream) {
				const micSource = audioContext.createMediaStreamSource(
					new MediaStream(micStream.getAudioTracks())
				);
				micSource.connect(monoMixer);
			}

			monoMixer.connect(destination);

			if (audioContext.state === 'suspended') {
				await audioContext.resume();
			}

			mixedStream = destination.stream;
			recordingActive = true;
			status = 'recording';

			[displayStream, micStream].forEach((stream) => {
				stream?.getAudioTracks().forEach((track) => {
					track.addEventListener('ended', handleSourceEnded, { once: true });
				});
			});

			startDurationCounter();
			await requestWakeLock();
			startRecorderChunk();
		} catch (error) {
			console.error('Error starting meeting audio capture:', error);
			toast.error(getErrorMessage(error));

			if (displayError || micError) {
				console.debug('Capture source errors', {
					displayError,
					micError
				});
			}

			status = 'idle';
			recordingActive = false;
			await cleanup();
		}
	};

	const stopCurrentRecorder = async () => {
		clearChunkTimer();
		await releaseWakeLock();

		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.stop();
			await currentRecorderStopped;
		} else {
			await currentRecorderStopped;
		}
	};

	const stopCapture = async () => {
		if (stopping || cancelled) {
			return;
		}

		stopping = true;
		recordingActive = false;
		status = 'stopping';
		stopDurationCounter();

		await stopCurrentRecorder();
		status = 'transcribing';
		await transcriptionChain;

		if (cancelled) {
			return;
		}

		const transcript = transcriptChunks
			.map((text) => text?.trim())
			.filter(Boolean)
			.join('\n\n');

		await cleanup();

		if (!transcript) {
			status = 'idle';
			stopping = false;
			toast.error($i18n.t('No transcript was created.'));
			return;
		}

		if (transcriptionErrors.length > 0) {
			toast.warning($i18n.t('Some audio chunks could not be transcribed.'));
		}

		const file = new File([transcript], `meeting-transcript-${formatFilenameDate()}.txt`, {
			type: 'text/plain'
		});

		completed = true;
		onConfirm({ file, text: transcript, errors: transcriptionErrors });
	};

	const cancelCapture = async () => {
		cancelled = true;
		stopping = true;
		recordingActive = false;
		stopDurationCounter();
		clearChunkTimer();
		retryingTranscriptions = 0;

		if (mediaRecorder?.state === 'recording') {
			mediaRecorder.stop();
			await currentRecorderStopped;
		}

		await cleanup();
		onCancel();
	};

	onMount(() => {
		document.addEventListener('visibilitychange', handleVisibilityChange);
	});

	onDestroy(() => {
		document.removeEventListener('visibilitychange', handleVisibilityChange);

		if (!completed) {
			cancelCapture();
		}
	});
</script>

<div
	class="rounded-2xl border border-gray-100 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-sm px-3 py-2.5 text-sm"
>
	<div class="flex gap-3">
		<div class="flex-1 min-w-0">
			<div class="font-medium text-gray-900 dark:text-gray-100">
				{$i18n.t('Capture Audio')}
			</div>
			<div class="mt-1 text-xs text-gray-500 dark:text-gray-400 leading-5">
				{#if status === 'idle'}
					{$i18n.t(
						'Select the Teams tab or window in the browser prompt. You can allow shared audio, microphone, or both.'
					)}
				{:else if status === 'starting'}
					{$i18n.t('Requesting shared audio and microphone access...')}
				{:else if status === 'recording'}
					{$i18n.t('Recording meeting audio and transcribing chunks in the background.')}
				{:else}
					{$i18n.t('Finalizing transcript...')}
				{/if}
			</div>

			{#if status !== 'idle'}
				<div class="mt-2 flex flex-wrap gap-2 text-xs text-gray-500 dark:text-gray-400">
					<div class="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-1">
						{$i18n.t('Duration')}: {formatSeconds(durationSeconds)}
					</div>
					<div class="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-1">
						{$i18n.t('Chunks')}: {chunkIndex}
					</div>
					<div class="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-1">
						{$i18n.t('Transcribed')}: {transcribedChunks}
					</div>
					<div class="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-1">
						{$i18n.t('Pending')}: {pendingTranscriptions}
					</div>
					{#if retryingTranscriptions > 0}
						<div class="rounded-full bg-gray-50 dark:bg-gray-800 px-2 py-1">
							{$i18n.t('Retrying')}: {retryingTranscriptions}
						</div>
					{/if}
					{#if failedChunks > 0}
						<div
							class="rounded-full bg-red-50 text-red-600 dark:bg-red-950/30 dark:text-red-300 px-2 py-1"
						>
							{$i18n.t('Failed')}: {failedChunks}
						</div>
					{/if}
				</div>
			{/if}
		</div>

		<button
			type="button"
			class="p-1.5 self-start rounded-full text-gray-500 hover:text-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 dark:hover:text-gray-200 transition"
			on:click={cancelCapture}
			aria-label={$i18n.t('Cancel')}
		>
			<XMark className="size-4" />
		</button>
	</div>

	<div class="mt-3 flex justify-end gap-2">
		{#if status === 'idle'}
			<button
				type="button"
				class="px-3 py-1.5 rounded-full bg-black text-white dark:bg-white dark:text-black hover:opacity-90 transition"
				on:click={startCapture}
			>
				{$i18n.t('Start')}
			</button>
		{:else if status === 'recording'}
			<button
				type="button"
				class="px-3 py-1.5 rounded-full bg-black text-white dark:bg-white dark:text-black hover:opacity-90 transition"
				on:click={stopCapture}
			>
				{$i18n.t('Stop and attach transcript')}
			</button>
		{:else}
			<button
				type="button"
				class="px-3 py-1.5 rounded-full bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400 cursor-not-allowed"
				disabled
			>
				{$i18n.t('Please wait...')}
			</button>
		{/if}
	</div>
</div>
