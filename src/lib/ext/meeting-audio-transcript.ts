export type CaptureSource = 'shared' | 'mic';

export type TranscriptionWord = {
	text: string;
	start: number;
	end: number;
};

export type TranscriptionSegment = {
	source: CaptureSource;
	speaker: string;
	text: string;
	start: number | null;
	end: number | null;
	chunkIndex: number;
	words?: TranscriptionWord[];
};

type ProviderWord = {
	text?: string | null;
	start?: number | null;
	end?: number | null;
	offsetMilliseconds?: number | null;
	durationMilliseconds?: number | null;
};

type ProviderSegment = {
	speaker?: string | null;
	text?: string | null;
	start?: number | null;
	end?: number | null;
	words?: ProviderWord[] | null;
};

export const normalizeTranscriptionSegments = ({
	res,
	source,
	index,
	chunkDurationMs,
	youLabel,
	sharedLabel
}: {
	res: any;
	source: CaptureSource;
	index: number;
	chunkDurationMs: number;
	youLabel: string;
	sharedLabel: string;
}): TranscriptionSegment[] => {
	const chunkStartSeconds = (index * chunkDurationMs) / 1000;
	const fallbackSpeaker = source === 'mic' ? youLabel : sharedLabel;
	const segments = Array.isArray(res?.segments) ? res.segments : [];

	const normalizeWords = (segment: ProviderSegment): TranscriptionWord[] => {
		const words = Array.isArray(segment.words) ? segment.words : [];

		return words
			.map((word: ProviderWord) => {
				const text = (word.text || '').trim();
				if (!text) {
					return null;
				}

				const relativeStart =
					typeof word.start === 'number'
						? word.start
						: typeof word.offsetMilliseconds === 'number'
							? word.offsetMilliseconds / 1000
							: null;
				const relativeEnd =
					typeof word.end === 'number'
						? word.end
						: typeof word.offsetMilliseconds === 'number' &&
							  typeof word.durationMilliseconds === 'number'
							? (word.offsetMilliseconds + word.durationMilliseconds) / 1000
							: null;

				if (relativeStart === null || relativeEnd === null) {
					return null;
				}

				return {
					text,
					start: chunkStartSeconds + relativeStart,
					end: chunkStartSeconds + relativeEnd
				};
			})
			.filter(Boolean) as TranscriptionWord[];
	};

	if (segments.length > 0) {
		return segments
			.map((segment: ProviderSegment) => {
				const text = (segment.text || '').trim();
				if (!text) {
					return null;
				}

				const start =
					typeof segment.start === 'number' ? chunkStartSeconds + segment.start : chunkStartSeconds;
				const end = typeof segment.end === 'number' ? chunkStartSeconds + segment.end : null;
				const words = normalizeWords(segment);

				const normalizedSegment: TranscriptionSegment = {
					source,
					speaker: source === 'mic' ? fallbackSpeaker : segment.speaker || fallbackSpeaker,
					text,
					start,
					end,
					chunkIndex: index
				};

				if (words.length > 0) {
					normalizedSegment.words = words;
				}

				return normalizedSegment;
			})
			.filter(Boolean) as TranscriptionSegment[];
	}

	const text = (res?.text || '').trim();
	if (!text) {
		return [];
	}

	return [
		{
			source,
			speaker: fallbackSpeaker,
			text,
			start: chunkStartSeconds,
			end: chunkStartSeconds + chunkDurationMs / 1000,
			chunkIndex: index
		}
	];
};

export const buildMeetingTranscript = (segments: TranscriptionSegment[]) => {
	const timelineSegments = splitSharedSegmentsAroundMicSegments(segments);
	const sortedSegments = [...timelineSegments].sort((a, b) => {
		const startDiff = (a.start ?? Number.MAX_SAFE_INTEGER) - (b.start ?? Number.MAX_SAFE_INTEGER);
		if (startDiff !== 0) {
			return startDiff;
		}

		return a.source.localeCompare(b.source);
	});

	const mergedSegments: TranscriptionSegment[] = [];
	for (const segment of sortedSegments) {
		const previous = mergedSegments[mergedSegments.length - 1];
		const gap =
			previous && previous.end !== null && segment.start !== null
				? segment.start - previous.end
				: Number.MAX_VALUE;

		if (
			previous &&
			previous.speaker === segment.speaker &&
			previous.source === segment.source &&
			gap <= 1.5
		) {
			previous.text = `${previous.text} ${segment.text}`;
			previous.end = segment.end ?? previous.end;
		} else {
			mergedSegments.push({ ...segment });
		}
	}

	return mergedSegments
		.map((segment) => `${formatTimestampRange(segment)}\n${segment.speaker}: ${segment.text}`)
		.join('\n\n');
};

const formatSeconds = (seconds: number) => {
	const minutes = Math.floor(seconds / 60);
	const remainingSeconds = seconds % 60;
	const formattedSeconds = remainingSeconds < 10 ? `0${remainingSeconds}` : remainingSeconds;
	return `${minutes}:${formattedSeconds}`;
};

const formatTimestamp = (seconds: number | null) => {
	if (seconds === null || Number.isNaN(seconds)) {
		return '--:--';
	}

	return formatSeconds(Math.max(0, Math.floor(seconds)));
};

const formatTimestampRange = (segment: TranscriptionSegment) => {
	const start = formatTimestamp(segment.start);
	const end = formatTimestamp(segment.end);

	return `[${start}-${end}]`;
};

const joinWords = (words: TranscriptionWord[]) =>
	words
		.map((word) => word.text)
		.join(' ')
		.replace(/\s+([,.!?;:])/g, '$1')
		.trim();

const splitSharedSegmentsAroundMicSegments = (segments: TranscriptionSegment[]) => {
	const micSegments = segments.filter(
		(segment) =>
			segment.source === 'mic' &&
			typeof segment.start === 'number' &&
			typeof segment.end === 'number'
	);

	if (micSegments.length === 0) {
		return segments;
	}

	return segments.flatMap((segment) => {
		const words = segment.words;
		if (
			segment.source !== 'shared' ||
			!words?.length ||
			typeof segment.start !== 'number' ||
			typeof segment.end !== 'number'
		) {
			return [segment];
		}

		const segmentStart = segment.start;
		const segmentEnd = segment.end;

		const boundaries = micSegments
			.flatMap((micSegment) => [micSegment.start, micSegment.end])
			.filter(
				(boundary): boundary is number =>
					typeof boundary === 'number' && boundary > segmentStart && boundary < segmentEnd
			)
			.sort((a, b) => a - b);

		if (boundaries.length === 0) {
			return [segment];
		}

		const pieces: TranscriptionSegment[] = [];
		let currentWords: TranscriptionWord[] = [];
		let boundaryIndex = 0;

		const flushCurrentWords = () => {
			if (currentWords.length === 0) {
				return;
			}

			const text = joinWords(currentWords);
			if (text) {
				pieces.push({
					...segment,
					text,
					start: currentWords[0].start,
					end: currentWords[currentWords.length - 1].end,
					words: [...currentWords]
				});
			}

			currentWords = [];
		};

		for (const word of words) {
			while (boundaryIndex < boundaries.length && word.start >= boundaries[boundaryIndex]) {
				flushCurrentWords();
				boundaryIndex += 1;
			}

			currentWords.push(word);
		}

		flushCurrentWords();

		return pieces.length > 0 ? pieces : [segment];
	});
};
