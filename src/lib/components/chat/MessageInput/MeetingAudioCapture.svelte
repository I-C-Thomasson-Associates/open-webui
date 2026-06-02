<script lang="ts">
	import { getContext, onDestroy, onMount } from 'svelte';
	import { toast } from 'svelte-sonner';

	import { config, settings } from '$lib/stores';
	import { transcribeAudio, transcribeCaptureAudio } from '$lib/apis/audio';
	import {
		buildMeetingTranscript,
		normalizeTranscriptionSegments,
		type CaptureSource,
		type TranscriptionSegment
	} from '$lib/ext/meeting-audio-transcript';

	import XMark from '$lib/components/icons/XMark.svelte';

	const i18n: any = getContext('i18n');

	export let chunkDurationMs = 5 * 60 * 1000;
	export let onCancel = () => {};
	export let onConfirm = (data: { file: File; text: string; errors: string[] }) => {};

	type CaptureStatus = 'idle' | 'starting' | 'recording' | 'stopping' | 'transcribing';

	type SourceState = {
		source: CaptureSource;
		stream: MediaStream;
	};

	type RecorderState = {
		recorder: MediaRecorder;
		stopped: Promise<void>;
	};

	let status: CaptureStatus = 'idle';
	let displayStream: MediaStream | null = null;
	let micStream: MediaStream | null = null;

	let durationSeconds = 0;
	let durationCounter: ReturnType<typeof setInterval> | null = null;
	let chunkTimer: ReturnType<typeof setTimeout> | null = null;

	let chunkIndex = 0;
	let activeSources: SourceState[] = [];
	let currentRecorders: RecorderState[] = [];
	let transcriptSegments: TranscriptionSegment[] = [];
	let transcriptionErrors: string[] = [];
	let pendingTranscriptions = 0;
	let transcribedChunks = 0;
	let failedChunks = 0;
	let retryingTranscriptions = 0;
	let transcriptionChain = Promise.resolve();
	let stoppingCurrentChunk = Promise.resolve();

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

	const clearChunkTimer = () => {
		if (chunkTimer) {
			clearTimeout(chunkTimer);
			chunkTimer = null;
		}
	};

	const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

	const transcribeChunkWithRetry = async (file: File, source: CaptureSource) => {
		let lastError;
		const diarize = source === 'shared';

		for (let attempt = 0; attempt <= transcriptionRetryDelaysMs.length; attempt++) {
			if (cancelled) {
				break;
			}

			try {
				try {
					return await transcribeCaptureAudio(
						localStorage.token,
						file,
						$settings?.audio?.stt?.language,
						{ diarize }
					);
				} catch (error: any) {
					if (error?.status === 404 || error?.status === 501) {
						return await transcribeAudio(localStorage.token, file, $settings?.audio?.stt?.language, {
							diarize
						});
					}

					throw error;
				}
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

		displayStream = null;
		micStream = null;
		activeSources = [];
		currentRecorders = [];
	};

	const enqueueTranscription = (
		blob: Blob,
		index: number,
		mimeType: string,
		source: CaptureSource
	) => {
		pendingTranscriptions += 1;
		const ext = getExtension(mimeType);
		const file = new File([blob], `meeting-${source}-audio-${index + 1}.${ext}`, {
			type: mimeType
		});

		transcriptionChain = transcriptionChain.then(async () => {
			if (cancelled) {
				pendingTranscriptions -= 1;
				return;
			}

			try {
				const res = await transcribeChunkWithRetry(file, source);
				const segments = normalizeTranscriptionSegments({
					res,
					source,
					index,
					chunkDurationMs,
					youLabel: $i18n.t('You'),
					sharedLabel: $i18n.t('Call Audio')
				});

				if (!cancelled && segments.length > 0) {
					transcriptSegments = [...transcriptSegments, ...segments];
					transcribedChunks += 1;
				}
			} catch (error) {
				console.error('Error transcribing meeting audio chunk:', error);
				if (!cancelled) {
					failedChunks += 1;
					transcriptionErrors = [
						...transcriptionErrors,
						$i18n.t('{{source}} chunk {{number}} failed to transcribe.', {
							source: source === 'mic' ? $i18n.t('Microphone') : $i18n.t('Shared audio'),
							number: index + 1
						})
					];
				}
			} finally {
				pendingTranscriptions -= 1;
			}
		});
	};

	const createRecorder = (sourceState: SourceState, index: number): RecorderState | null => {
		if (!hasLiveAudioTracks(sourceState.stream)) {
			return null;
		}

		const parts: Blob[] = [];
		const mimeType = mimeTypes.find((type) => MediaRecorder.isTypeSupported(type));
		const recorderOptions = mimeType ? { mimeType } : undefined;
		const recorder = new MediaRecorder(sourceState.stream, recorderOptions);

		const stopped = new Promise<void>((resolve) => {
			recorder.ondataavailable = (event) => {
				if (event.data.size > 0) {
					parts.push(event.data);
				}
			};

			recorder.onstop = () => {
				const recordedMimeType = recorder.mimeType || parts[0]?.type || 'audio/webm';
				if (!cancelled && parts.length > 0) {
					const blob = new Blob(parts, { type: recordedMimeType });
					enqueueTranscription(blob, index, recordedMimeType, sourceState.source);
				}

				resolve();
			};
		});

		recorder.start();

		return { recorder, stopped };
	};

	const stopCurrentChunk = async () => {
		clearChunkTimer();

		const recorders = currentRecorders;
		currentRecorders = [];

		for (const { recorder } of recorders) {
			if (recorder.state === 'recording') {
				recorder.stop();
			}
		}

		await Promise.all(recorders.map(({ stopped }) => stopped));
	};

	const startRecorderChunk = () => {
		if (!recordingActive || stopping || cancelled) {
			return;
		}

		const liveSources = activeSources.filter((source) => hasLiveAudioTracks(source.stream));
		if (liveSources.length === 0) {
			sourceEnded = true;
			toast.warning($i18n.t('Audio capture ended. Finalizing transcript.'));
			stopCapture();
			return;
		}

		const currentChunkIndex = chunkIndex;
		chunkIndex += 1;
		currentRecorders = liveSources
			.map((source) => createRecorder(source, currentChunkIndex))
			.filter(Boolean) as RecorderState[];

		chunkTimer = setTimeout(() => {
			if (!recordingActive || stopping || cancelled) {
				return;
			}

			stoppingCurrentChunk = stopCurrentChunk().then(() => {
				if (recordingActive && !stopping && !cancelled && !sourceEnded) {
					startRecorderChunk();
				}
			});
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
		activeSources = [];
		currentRecorders = [];
		transcriptSegments = [];
		transcriptionErrors = [];
		pendingTranscriptions = 0;
		transcribedChunks = 0;
		failedChunks = 0;
		retryingTranscriptions = 0;
		transcriptionChain = Promise.resolve();
		stoppingCurrentChunk = Promise.resolve();
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
						autoGainControl: false
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

			if (hasDisplayAudio && displayStream) {
				activeSources = [
					...activeSources,
					{
						source: 'shared',
						stream: new MediaStream(displayStream.getAudioTracks())
					}
				];
			}

			if (hasMicAudio && micStream) {
				activeSources = [
					...activeSources,
					{
						source: 'mic',
						stream: new MediaStream(micStream.getAudioTracks())
					}
				];
			}

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

	const stopCapture = async () => {
		if (stopping || cancelled) {
			return;
		}

		stopping = true;
		recordingActive = false;
		status = 'stopping';
		stopDurationCounter();

		await stoppingCurrentChunk;
		await stopCurrentChunk();
		status = 'transcribing';
		await transcriptionChain;

		if (cancelled) {
			return;
		}

		const transcript = buildMeetingTranscript(transcriptSegments);

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

		await stoppingCurrentChunk;
		await stopCurrentChunk();
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
						'Select the Teams tab or window in the browser prompt. Shared audio and microphone are recorded separately, then aligned by timestamp.'
					)}
				{:else if status === 'starting'}
					{$i18n.t('Requesting shared audio and microphone access...')}
				{:else if status === 'recording'}
					{$i18n.t('Recording separate audio sources and transcribing chunks in the background.')}
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
						{$i18n.t('Sources')}: {activeSources.length}
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
