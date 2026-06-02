"""Salas O'Brien meeting audio transcription extensions."""

import json

import requests


AZURE_WORD_TIMESTAMP_OPTION_KEYS = {
    'wordLevelTimestampsEnabled',
    'displayFormWordLevelTimestampsEnabled',
}


def get_azure_max_speakers(config):
    try:
        max_speakers = int(config.AUDIO_STT_AZURE_MAX_SPEAKERS or 3)
    except (TypeError, ValueError):
        max_speakers = 3

    return max(2, min(max_speakers, 35))


def build_azure_definition(locales, max_speakers, diarize=True):
    if not locales:
        return {}

    definition = {
        'locales': [locale.strip() for locale in locales.split(',') if locale.strip()],
        'wordLevelTimestampsEnabled': True,
        'displayFormWordLevelTimestampsEnabled': True,
    }

    if diarize:
        definition['diarization'] = {'maxSpeakers': max_speakers, 'enabled': True}

    return definition


def post_azure_fast_transcription(file_path, url, api_key, definition, timeout, log):
    def _post(definition_payload):
        with open(file_path, 'rb') as audio_file:
            return requests.post(
                url=url,
                files={'audio': audio_file},
                data={'definition': json.dumps(definition_payload)},
                headers={
                    'Ocp-Apim-Subscription-Key': api_key,
                },
                timeout=timeout,
            )

    response = _post(definition)
    if response.status_code != 400 or not AZURE_WORD_TIMESTAMP_OPTION_KEYS.intersection(
        definition
    ):
        return response

    try:
        error_response = response.json()
        azure_code = error_response.get('innerError', {}).get(
            'code', error_response.get('code')
        )
    except Exception:
        azure_code = None

    if azure_code not in {
        'InvalidParameter',
        'InvalidParameterValue',
        'InvalidRequestBodyFormat',
    }:
        return response

    log.warning('Azure STT rejected word timestamp options; retrying without them')
    fallback_definition = {
        key: value
        for key, value in definition.items()
        if key not in AZURE_WORD_TIMESTAMP_OPTION_KEYS
    }
    return _post(fallback_definition)


def format_azure_transcription_response(response, diarize=False):
    if not response.get('combinedPhrases'):
        raise ValueError('No transcription found in response')

    transcript = response['combinedPhrases'][0].get('text', '').strip()
    if not transcript:
        raise ValueError('Empty transcript in response')

    diarization = {
        'requested': bool(diarize),
        'supported': True,
        'applied': False,
        'provider': 'azure',
    }
    data = {'text': transcript, 'diarization': diarization}
    diagnostics = _get_azure_diagnostics(response.get('phrases', []))
    data['diagnostics'] = diagnostics

    phrase_segments = _format_phrase_segments(response.get('phrases', []))
    if phrase_segments:
        data['segments'] = phrase_segments

    if diarize:
        diarized_text, segments = _format_diarized_phrases(response.get('phrases', []))
        if diarized_text:
            data = {
                'text': diarized_text,
                'segments': segments,
                'diagnostics': diagnostics,
                'diarization': {
                    **diarization,
                    'applied': True,
                },
            }
        else:
            data['diarization']['error'] = 'Azure returned no speaker segments'

    return data


def _format_azure_words(phrase):
    words = []

    for word in phrase.get('words') or []:
        text = (word.get('text') or '').strip()
        if not text:
            continue

        offset_ms = word.get('offsetMilliseconds')
        duration_ms = word.get('durationMilliseconds')
        start = offset_ms / 1000 if isinstance(offset_ms, int) else None
        end = (
            (offset_ms + duration_ms) / 1000
            if isinstance(offset_ms, int) and isinstance(duration_ms, int)
            else None
        )

        words.append(
            {
                'text': text,
                'start': start,
                'end': end,
            }
        )

    return words


def _get_azure_diagnostics(phrases):
    phrases = phrases or []
    durations = [
        phrase.get('durationMilliseconds') / 1000
        for phrase in phrases
        if isinstance(phrase.get('durationMilliseconds'), int)
    ]

    return {
        'provider': 'azure',
        'phraseCount': len(phrases),
        'wordCount': sum(len(phrase.get('words') or []) for phrase in phrases),
        'phrasesWithWords': sum(1 for phrase in phrases if phrase.get('words')),
        'longestPhraseSeconds': max(durations) if durations else None,
        'diarizedPhraseCount': sum(
            1 for phrase in phrases if phrase.get('speaker') is not None
        ),
    }


def _format_diarized_phrases(phrases):
    voice_labels = {}
    segments = []

    for phrase in phrases or []:
        text = (phrase.get('text') or '').strip()
        if not text:
            continue

        speaker = phrase.get('speaker')
        if speaker is None:
            label = 'Unknown'
        else:
            if speaker not in voice_labels:
                voice_labels[speaker] = f'Voice {len(voice_labels) + 1}'
            label = voice_labels[speaker]

        offset_ms = phrase.get('offsetMilliseconds')
        duration_ms = phrase.get('durationMilliseconds')
        start = offset_ms / 1000 if isinstance(offset_ms, int) else None
        end = (
            (offset_ms + duration_ms) / 1000
            if isinstance(offset_ms, int) and isinstance(duration_ms, int)
            else None
        )

        segment = {
            'speaker': label,
            'speaker_id': speaker,
            'text': text,
            'start': start,
            'end': end,
        }
        words = _format_azure_words(phrase)
        if words:
            segment['words'] = words

        segments.append(segment)

    diarized_segments = [
        segment for segment in segments if segment.get('speaker_id') is not None
    ]
    if not diarized_segments:
        return '', []

    return (
        '\n\n'.join([f'{segment["speaker"]}: {segment["text"]}' for segment in segments]),
        segments,
    )


def _format_phrase_segments(phrases):
    segments = []

    for phrase in phrases or []:
        text = (phrase.get('text') or '').strip()
        if not text:
            continue

        offset_ms = phrase.get('offsetMilliseconds')
        duration_ms = phrase.get('durationMilliseconds')
        start = offset_ms / 1000 if isinstance(offset_ms, int) else None
        end = (
            (offset_ms + duration_ms) / 1000
            if isinstance(offset_ms, int) and isinstance(duration_ms, int)
            else None
        )

        segment = {
            'speaker': None,
            'speaker_id': None,
            'text': text,
            'start': start,
            'end': end,
        }

        words = _format_azure_words(phrase)
        if words:
            segment['words'] = words

        segments.append(segment)

    return segments
