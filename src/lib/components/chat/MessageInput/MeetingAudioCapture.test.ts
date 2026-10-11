import { readFileSync } from 'node:fs';
import { File } from 'node:buffer';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { compile, parse } from 'svelte/compiler';
import { describe, expect, it, vi } from 'vitest';
import {
	buildMeetingTranscript,
	normalizeTranscriptionSegments
} from '$lib/ext/meeting-audio-transcript';

const captureSource = readFileSync(
	new URL('./MeetingAudioCapture.svelte', import.meta.url),
	'utf8'
);
const inputSource = readFileSync(new URL('../MessageInput.svelte', import.meta.url), 'utf8');
const deferred = () => {
	let resolve!: (value: any) => void;
	let reject!: (error: any) => void;
	const promise = new Promise((done, fail) => {
		resolve = done;
		reject = fail;
	});
	return { promise, resolve, reject };
};
const settle = async () => {
	for (let i = 0; i < 20; i++) await Promise.resolve();
};
const translate = (text: string) => text;

function execute(script: string, context: any, expose: string) {
	const code = ts.transpileModule(script, {
		compilerOptions: { target: ts.ScriptTarget.ES2022 }
	}).outputText;
	return runInNewContext(code + '\n' + expose, context);
}

function stream(audio = true) {
	const track: any = {
		readyState: 'live',
		stop: vi.fn(() => {
			track.readyState = 'ended';
		}),
		addEventListener: vi.fn()
	};
	return { track, getTracks: () => [track], getAudioTracks: () => (audio ? [track] : []) };
}

function capture(overrides: any = {}) {
	let destroy = () => {};
	let timerId = 0;
	const timers = new Map<number, () => void>();
	const intervals = new Map<number, () => void>();
	const recorders: any[] = [];
	class Recorder {
		static isTypeSupported = () => true;
		state = 'inactive';
		mimeType = 'audio/webm';
		ondataavailable: any;
		onstop: any;
		constructor() {
			recorders.push(this);
		}
		start() {
			this.state = 'recording';
		}
		stop() {
			this.state = 'inactive';
			this.ondataavailable({ data: new Blob(['audio'], { type: this.mimeType }) });
			this.onstop();
		}
	}
	const context: any = {
		getContext: () => ({}),
		onMount: () => {},
		onDestroy: (fn: () => void) => {
			destroy = fn;
		},
		$i18n: { t: translate },
		$config: {},
		$settings: {},
		localStorage: { token: 'test' },
		navigator: {
			mediaDevices: {
				getDisplayMedia: vi.fn().mockResolvedValue(stream()),
				getUserMedia: vi.fn().mockResolvedValue(stream())
			}
		},
		document: { visibilityState: 'visible', removeEventListener: vi.fn() },
		MediaStream: class {
			constructor(private tracks: any[]) {}
			getAudioTracks() {
				return this.tracks;
			}
		},
		MediaRecorder: Recorder,
		Blob,
		File,
		console: { ...console, error: vi.fn(), debug: vi.fn() },
		toast: { error: vi.fn(), warning: vi.fn() },
		fileSaver: { saveAs: vi.fn() },
		transcribeCaptureAudio: vi.fn().mockResolvedValue({ text: 'Meeting transcript' }),
		transcribeAudio: vi.fn(),
		buildMeetingTranscript,
		normalizeTranscriptionSegments,
		setTimeout: vi.fn((fn: () => void) => {
			timers.set(++timerId, fn);
			return timerId;
		}),
		clearTimeout: vi.fn((id: number) => timers.delete(id)),
		setInterval: vi.fn((fn: () => void) => {
			intervals.set(++timerId, fn);
			return timerId;
		}),
		clearInterval: vi.fn((id: number) => intervals.delete(id)),
		...overrides
	};
	const script = captureSource
		.match(/<script lang="ts">([\s\S]*?)<\/script>/)![1]
		.replace(/\bimport[\s\S]*?from\s+['"][^'"]+['"];?/g, '')
		.replace(/\bexport\s+/g, '');
	const api = execute(
		script,
		context,
		`({ startCapture, stopCapture, cancelCapture, attachTranscript,
		downloadTranscript, handleVisibilityChange, requestWakeLock,
		confirm: (fn) => onConfirm = fn, cancel: (fn) => onCancel = fn,
		state: () => ({ status, recordingActive, completedResult, attaching, attachmentFailed, wakeLock,
			pendingTranscriptions, transcribedChunks, activeSources }) })`
	);
	return { ...api, context, timers, intervals, recorders, destroy: () => destroy() };
}

function upload(overrides: any = {}) {
	// Execute the actual bounded handler, not a reimplementation or a mounted component.
	const script = inputSource.slice(
		inputSource.indexOf('\tconst getFilesystemUploadTerminal ='),
		inputSource.indexOf('\tconst inputFilesHandler =')
	);
	const context: any = {
		$_user: { role: 'admin' },
		$selectedTerminalId: null,
		$terminalServers: [],
		$settings: {},
		fileUploadCapableModels: ['model'],
		selectedModelIds: ['model'],
		$temporaryChatEnabled: false,
		$i18n: { t: translate },
		toast: { error: vi.fn(), warning: vi.fn() },
		uuidv4: vi.fn(() => 'temp-id'),
		files: [],
		onUpdate: vi.fn(),
		chatId: '',
		localStorage: { token: 'test' },
		console: { ...console, log: vi.fn(), warn: vi.fn() },
		uploadFile: vi.fn().mockResolvedValue({ id: 'uploaded-id', meta: {} }),
		getCwd: vi.fn().mockResolvedValue({ cwd: '/workspace' }),
		uploadNewFileToTerminal: vi
			.fn()
			.mockResolvedValue({ path: '/workspace/transcript.txt', size: 20 }),
		showFileNavDir: { set: vi.fn() },
		extractContentFromFile: vi.fn().mockResolvedValue('transcript'),
		...overrides
	};
	const api = execute(script, context, '({ uploadFileHandler })');
	return { ...api, context };
}
const transcriptFile = () => new File(['transcript'], 'transcript.txt', { type: 'text/plain' });

describe('T9 Capture Audio lifecycle', () => {
	it.each(['cancel', 'destroy'])(
		'stops late display tracks after %s without asking for mic',
		async (action) => {
			const pending = deferred();
			const c = capture();
			c.context.navigator.mediaDevices.getDisplayMedia.mockReturnValue(pending.promise);
			const starting = c.startCapture();
			if (action === 'cancel') await c.cancelCapture();
			else c.destroy();
			const late = stream();
			pending.resolve(late);
			await starting;
			await settle();
			expect(late.track.stop).toHaveBeenCalledOnce();
			expect(c.context.navigator.mediaDevices.getUserMedia).not.toHaveBeenCalled();
			expect(c.recorders).toHaveLength(0);
			expect(c.timers.size + c.intervals.size).toBe(0);
			await c.startCapture();
			expect(c.context.navigator.mediaDevices.getDisplayMedia).toHaveBeenCalledOnce();
		}
	);

	it('does not request mic after a cancelled display rejection', async () => {
		const pending = deferred();
		const c = capture();
		c.context.navigator.mediaDevices.getDisplayMedia.mockReturnValue(pending.promise);
		const starting = c.startCapture();
		await c.cancelCapture();
		pending.reject(new Error('denied'));
		await starting;
		expect(c.context.navigator.mediaDevices.getUserMedia).not.toHaveBeenCalled();
	});

	it.each(['cancel', 'destroy'])('stops existing display and late mic after %s', async (action) => {
		const pending = deferred();
		const c = capture();
		const display = stream();
		c.context.navigator.mediaDevices.getDisplayMedia.mockResolvedValue(display);
		c.context.navigator.mediaDevices.getUserMedia.mockReturnValue(pending.promise);
		const starting = c.startCapture();
		await settle();
		if (action === 'cancel') await c.cancelCapture();
		else c.destroy();
		const late = stream();
		pending.resolve(late);
		await starting;
		await settle();
		expect(display.track.stop).toHaveBeenCalled();
		expect(late.track.stop).toHaveBeenCalledOnce();
		expect(c.recorders).toHaveLength(0);
		expect(c.timers.size + c.intervals.size).toBe(0);
	});

	it.each(['cancel', 'destroy', 'stop'])(
		'releases a late initial wake lock after %s',
		async (action) => {
			const pending = deferred();
			const c = capture();
			c.context.navigator.wakeLock = { request: vi.fn().mockReturnValue(pending.promise) };
			const starting = c.startCapture();
			await settle();
			if (action === 'cancel') await c.cancelCapture();
			else if (action === 'destroy') c.destroy();
			else await c.stopCapture();
			const lock = { release: vi.fn().mockResolvedValue(undefined), addEventListener: vi.fn() };
			pending.resolve(lock);
			await starting;
			await settle();
			expect(lock.release).toHaveBeenCalledOnce();
			expect(c.state().wakeLock).toBeNull();
			expect(c.recorders).toHaveLength(0);
			expect(c.timers.size + c.intervals.size).toBe(0);
		}
	);

	it('releases late visibility locks and stops tracks without waiting for lock release', async () => {
		const c = capture();
		await c.startCapture();
		const pending = deferred();
		const release = deferred();
		c.context.navigator.wakeLock = { request: vi.fn().mockReturnValue(pending.promise) };
		const visible = c.handleVisibilityChange();
		await c.cancelCapture();
		const lock = { release: vi.fn().mockReturnValue(release.promise) };
		pending.resolve(lock);
		await settle();
		expect(lock.release).toHaveBeenCalledOnce();
		expect(c.timers.size + c.intervals.size).toBe(0);
		release.resolve(undefined);
		await visible;
	});

	it('stops capture tracks even while an acquired wake-lock release is pending', async () => {
		const c = capture();
		const display = stream();
		const mic = stream();
		const release = deferred();
		c.context.navigator.mediaDevices.getDisplayMedia.mockResolvedValue(display);
		c.context.navigator.mediaDevices.getUserMedia.mockResolvedValue(mic);
		c.context.navigator.wakeLock = {
			request: vi.fn().mockResolvedValue({
				release: vi.fn().mockReturnValue(release.promise),
				addEventListener: vi.fn()
			})
		};
		await c.startCapture();
		const cancelling = c.cancelCapture();
		await settle();
		expect(display.track.stop).toHaveBeenCalled();
		expect(mic.track.stop).toHaveBeenCalled();
		expect(c.timers.size + c.intervals.size).toBe(0);
		release.resolve(undefined);
		await cancelling;
	});

	it('keeps one wake lock across concurrent visibility requests and reacquires after release', async () => {
		const c = capture();
		await c.startCapture();
		const first = deferred();
		const second = deferred();
		const request = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
		c.context.navigator.wakeLock = { request };
		const a = c.handleVisibilityChange();
		const b = c.handleVisibilityChange();
		const lock = { release: vi.fn().mockResolvedValue(undefined), addEventListener: vi.fn() };
		const extra = { release: vi.fn().mockResolvedValue(undefined), addEventListener: vi.fn() };
		first.resolve(lock);
		await a;
		second.resolve(extra);
		await b;
		expect(c.state().wakeLock).toBe(lock);
		expect(extra.release).toHaveBeenCalledOnce();
		lock.addEventListener.mock.calls[0][1]();
		request.mockResolvedValue(extra);
		await c.handleVisibilityChange();
		expect(c.state().wakeLock).toBe(extra);
		await c.cancelCapture();
		expect(extra.release).toHaveBeenCalledTimes(2);
	});

	it('does not invoke fallback transcription after cancellation of an in-flight request', async () => {
		const pending = deferred();
		const c = capture();
		c.context.transcribeCaptureAudio.mockReturnValue(pending.promise);
		await c.startCapture();
		const stopping = c.stopCapture();
		await settle();
		await c.cancelCapture();
		pending.reject({ status: 404 });
		await stopping;
		expect(c.context.transcribeAudio).not.toHaveBeenCalled();
		expect(c.state().completedResult).toBeNull();
	});

	it.each(['mic', 'shared'])(
		'preserves %s-only recording and chunk transcript attachment',
		async (source) => {
			const c = capture();
			const rejected = source === 'mic' ? 'getDisplayMedia' : 'getUserMedia';
			c.context.navigator.mediaDevices[rejected].mockRejectedValue(new Error('denied'));
			const confirm = vi.fn().mockResolvedValue(true);
			c.confirm(confirm);
			await c.startCapture();
			expect(c.state().activeSources.map((s: any) => s.source)).toEqual([source]);
			expect(c.recorders).toHaveLength(1);
			const nextChunk = [...c.timers.values()][0];
			nextChunk();
			await settle();
			expect(c.recorders).toHaveLength(2);
			await c.stopCapture();
			expect(c.context.transcribeCaptureAudio).toHaveBeenCalledTimes(2);
			expect(c.context.transcribeCaptureAudio.mock.calls[0][3]).toEqual({
				diarize: source === 'shared'
			});
			expect(confirm).toHaveBeenCalledOnce();
			expect(confirm.mock.calls[0][0].text).toContain('Meeting transcript');
			expect(c.state().pendingTranscriptions).toBe(0);
			expect(c.timers.size + c.intervals.size).toBe(0);
		}
	);

	it.each([false, null, 'throw'])(
		'retains the same transcript after attachment result %s for download/retry',
		async (result) => {
			const c = capture();
			const confirm =
				result === 'throw'
					? vi.fn().mockRejectedValue(new Error('upload failed'))
					: vi.fn().mockResolvedValue(result);
			c.confirm(confirm);
			await c.startCapture();
			await c.stopCapture();
			const saved = c.state().completedResult;
			expect(c.state().status).toBe('completed');
			expect(c.state().attachmentFailed).toBe(true);
			c.downloadTranscript();
			expect(c.context.fileSaver.saveAs).toHaveBeenCalledWith(saved.file, saved.file.name);
			confirm.mockResolvedValue(true);
			await c.attachTranscript();
			expect(confirm.mock.calls[1][0]).toBe(saved);
			expect(c.state().attachmentFailed).toBe(false);
			expect(c.context.transcribeCaptureAudio).toHaveBeenCalledTimes(2);
		}
	);

	it('prevents concurrent attachment retries and further attachment after unmount', async () => {
		const pending = deferred();
		const c = capture();
		const confirm = vi.fn().mockReturnValue(pending.promise);
		c.confirm(confirm);
		await c.startCapture();
		const stopping = c.stopCapture();
		await settle();
		await c.attachTranscript();
		expect(confirm).toHaveBeenCalledOnce();
		pending.resolve(false);
		await stopping;
		c.destroy();
		await c.attachTranscript();
		expect(confirm).toHaveBeenCalledOnce();
	});

	it('does not confirm after unmount while final wake-lock release is pending', async () => {
		const release = deferred();
		const c = capture();
		const lock = { release: vi.fn().mockReturnValue(release.promise), addEventListener: vi.fn() };
		c.context.navigator.wakeLock = { request: vi.fn().mockResolvedValue(lock) };
		const confirm = vi.fn();
		c.confirm(confirm);
		await c.startCapture();
		const stopping = c.stopCapture();
		await settle();
		c.destroy();
		release.resolve(undefined);
		await stopping;
		await settle();
		expect(confirm).not.toHaveBeenCalled();
	});
});

describe('T9 explicit upload success contract', () => {
	it.each(['regular', 'terminal', 'temporary'])(
		'returns true only for retained successful %s attachment',
		async (mode) => {
			const u = upload(
				mode === 'terminal'
					? {
							$selectedTerminalId: 'terminal',
							$terminalServers: [
								{ id: 'terminal', url: 'local', config: { chat_uploads: 'filesystem' } }
							]
						}
					: mode === 'temporary'
						? { $temporaryChatEnabled: true }
						: {}
			);
			expect(await u.uploadFileHandler(transcriptFile(), true, { context: 'full' })).toBe(true);
			expect(u.context.files).toHaveLength(1);
			expect(u.context.files[0].context).toBe('full');
			expect(u.context.onUpdate).toHaveBeenCalledOnce();
		}
	);

	it('preserves enabled user-configured filesystem terminal uploads', async () => {
		const u = upload({
			$selectedTerminalId: 'configured',
			fileUploadCapableModels: [],
			$settings: {
				terminalServers: [
					{ url: 'configured', enabled: true, config: { chat_uploads: 'filesystem' } }
				]
			}
		});
		expect(await u.uploadFileHandler(transcriptFile())).toBe(true);
		expect(u.context.uploadFile).not.toHaveBeenCalled();
		expect(u.context.uploadNewFileToTerminal).toHaveBeenCalledOnce();
	});

	it.each(['null', 'throw', 'missing-id', 'error-without-id'])(
		'returns false and cleans regular upload after %s',
		async (failure) => {
			const u = upload();
			if (failure === 'throw') u.context.uploadFile.mockRejectedValue(new Error('failed'));
			else
				u.context.uploadFile.mockResolvedValue(
					failure === 'null'
						? null
						: failure === 'error-without-id'
							? { error: 'storage failed' }
							: {}
				);
			expect(await u.uploadFileHandler(transcriptFile())).toBe(false);
			expect(u.context.files).toHaveLength(0);
			expect(u.context.onUpdate).toHaveBeenCalledOnce();
		}
	);

	it('retains an ID-bearing ordinary upload and warns when processing fails', async () => {
		const stored = { id: 'stored-id', error: 'processing failed', meta: {} };
		const u = upload({ uploadFile: vi.fn().mockResolvedValue(stored) });
		expect(await u.uploadFileHandler(transcriptFile())).toBe(true);
		expect(u.context.files).toHaveLength(1);
		expect(u.context.files[0]).toMatchObject({
			id: 'stored-id',
			status: 'uploaded',
			error: '',
			file: stored
		});
		expect(u.context.files[0].file).toBe(stored);
		expect(u.context.toast.warning).toHaveBeenCalledWith('processing failed');
		expect(u.context.toast.error).not.toHaveBeenCalled();
		expect(u.context.onUpdate).toHaveBeenCalledOnce();
	});

	it.each([
		undefined,
		{ status: 'failed' },
		{ content: 'partial', metadata: { source: 'stored' } }
	])('preserves known full-context transcript with processing data %j', async (data) => {
		const stored = { id: 'stored-id', error: 'processing failed', meta: {}, data };
		const u = upload({ uploadFile: vi.fn().mockResolvedValue(stored) });
		expect(
			await u.uploadFileHandler(transcriptFile(), true, {
				context: 'full',
				content: 'Complete local transcript'
			})
		).toBe(true);
		expect(u.context.files[0].file.data).toEqual({
			...data,
			content: 'Complete local transcript'
		});
		expect(u.context.files[0].file.id).toBe('stored-id');
		expect(u.context.files[0].file.error).toBe('processing failed');
		expect(stored.data).toBe(data);
		expect(u.context.toast.warning).toHaveBeenCalledOnce();
	});

	it('uses known transcript text in temporary chat without requiring extraction', async () => {
		const u = upload({ $temporaryChatEnabled: true });
		u.context.extractContentFromFile.mockRejectedValue(new Error('extraction failed'));
		expect(
			await u.uploadFileHandler(transcriptFile(), true, {
				context: 'full',
				content: 'Complete local transcript'
			})
		).toBe(true);
		expect(u.context.files[0]).toMatchObject({
			type: 'text',
			context: 'full',
			content: 'Complete local transcript',
			status: 'uploaded'
		});
		expect(u.context.extractContentFromFile).not.toHaveBeenCalled();
		expect(u.context.uploadFile).not.toHaveBeenCalled();
	});

	it.each(['null', 'throw', 'missing-path'])(
		'returns false and cleans terminal upload after %s',
		async (failure) => {
			const u = upload({
				$selectedTerminalId: 'terminal',
				$terminalServers: [{ id: 'terminal', url: 'local', config: { chat_uploads: 'filesystem' } }]
			});
			if (failure === 'throw')
				u.context.uploadNewFileToTerminal.mockRejectedValue(new Error('failed'));
			else u.context.uploadNewFileToTerminal.mockResolvedValue(failure === 'null' ? null : {});
			expect(await u.uploadFileHandler(transcriptFile())).toBe(false);
			expect(u.context.files).toHaveLength(0);
			expect(u.context.onUpdate).toHaveBeenCalledOnce();
		}
	);

	it.each(['null', 'undefined', 'throw'])(
		'returns false and cleans temporary extraction after %s',
		async (failure) => {
			const u = upload({ $temporaryChatEnabled: true });
			if (failure === 'throw')
				u.context.extractContentFromFile.mockRejectedValue(new Error('failed'));
			else
				u.context.extractContentFromFile.mockResolvedValue(failure === 'null' ? null : undefined);
			expect(await u.uploadFileHandler(transcriptFile())).toBe(false);
			expect(u.context.files).toHaveLength(0);
			expect(u.context.onUpdate).toHaveBeenCalledOnce();
		}
	);

	it.each(['permission', 'model', 'empty'])(
		'preserves early %s validation without adding attachments',
		async (failure) => {
			const u = upload(
				failure === 'permission'
					? { $_user: { role: 'user', permissions: { chat: { file_upload: false } } } }
					: failure === 'model'
						? { fileUploadCapableModels: [] }
						: {}
			);
			expect(
				await u.uploadFileHandler(
					failure === 'empty' ? new File([], 'empty.txt') : transcriptFile()
				)
			).toBe(false);
			expect(u.context.files).toHaveLength(0);
			expect(u.context.uploadFile).not.toHaveBeenCalled();
		}
	);

	it('returns false if the attachment is removed while upload is pending', async () => {
		const pending = deferred();
		const u = upload();
		u.context.uploadFile.mockReturnValue(pending.promise);
		const uploading = u.uploadFileHandler(transcriptFile());
		u.context.files = [];
		pending.resolve({ id: 'id', meta: {} });
		expect(await uploading).toBe(false);
	});

	it('executes the actual parent callback: only success closes and focuses', async () => {
		const ast: any = parse(inputSource, { modern: true });
		let callback: any;
		const visit = (node: any) => {
			if (!node || typeof node !== 'object') return;
			if (node.type === 'Component' && node.name === 'MeetingAudioCapture')
				callback = node.attributes.find((a: any) => a.name === 'onConfirm').value.expression;
			for (const value of Object.values(node)) {
				if (Array.isArray(value)) value.forEach(visit);
				else if (value && typeof value === 'object') visit(value);
			}
		};
		visit(ast);
		expect(callback).toBeTruthy();
		const context: any = {
			uploadFileHandler: vi.fn().mockResolvedValue(false),
			meetingAudioCapture: true,
			tick: vi.fn().mockResolvedValue(undefined),
			document: { getElementById: vi.fn(() => ({ focus: vi.fn() })) }
		};
		const confirm = execute(
			'',
			context,
			'(' + inputSource.slice(callback.start, callback.end) + ')'
		);
		const result = { file: transcriptFile(), text: 'Complete local transcript' };
		expect(await confirm(result)).toBe(false);
		expect(context.uploadFileHandler).toHaveBeenCalledWith(result.file, true, {
			context: 'full',
			content: result.text
		});
		expect(context.meetingAudioCapture).toBe(true);
		expect(context.tick).not.toHaveBeenCalled();
		context.uploadFileHandler.mockResolvedValue(true);
		expect(await confirm(result)).toBe(true);
		expect(context.meetingAudioCapture).toBe(false);
		expect(context.tick).toHaveBeenCalledOnce();

		// Trace the real callback through the real upload handler, not just a boolean mock.
		const u = upload({
			uploadFile: vi.fn().mockResolvedValue({
				id: 'stored-id',
				error: 'extraction failed',
				meta: {}
			})
		});
		context.uploadFileHandler = u.uploadFileHandler;
		context.meetingAudioCapture = true;
		expect(await confirm(result)).toBe(true);
		expect(context.meetingAudioCapture).toBe(false);
		expect(u.context.files[0].file.data.content).toBe(result.text);
		expect(u.context.toast.warning).toHaveBeenCalledWith('extraction failed');
	});
});

describe('T9 Svelte compilation evidence (not mounted DOM)', () => {
	it.each([
		['MeetingAudioCapture.svelte', captureSource],
		['MessageInput.svelte', inputSource]
	])('compiles %s', (filename, source) => {
		expect(() => compile(source, { filename, generate: 'client' })).not.toThrow();
	});
});
