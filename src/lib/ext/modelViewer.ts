import { writable } from 'svelte/store';
import { WEBUI_API_BASE_URL } from '$lib/constants';

/** What a Model viewer tab saves: identifiers only, never a token. */
export type ModelViewerRef = {
	serverId: string;
	projectId: string;
	versionId: string;
	region?: string | null;
	name?: string;
};

export type ModelViewerCommand = {
	action:
		| 'isolate'
		| 'hide'
		| 'show_all'
		| 'select'
		| 'clear_selection'
		| 'fit'
		| 'color'
		| 'clear_colors'
		| 'reset_view';
	db_ids?: number[];
	search?: string;
	search_property?: string;
	color?: string;
	version_id?: string;
};

export type ViewerToken = { access_token: string; expires_in: number; urn: string };

// Pinned major: v8 drops APIs used below.
const VIEWER_BASE = 'https://developer.api.autodesk.com/modelderivative/v2/viewers/7.*';
const ACTIONS = new Set([
	'isolate',
	'hide',
	'show_all',
	'select',
	'clear_selection',
	'fit',
	'color',
	'clear_colors',
	'reset_view'
]);
const text = (value: unknown, max: number) =>
	typeof value === 'string' && value.length > 0 && value.length <= max;

export function parseModelViewerRef(data: unknown): ModelViewerRef | null {
	const d = data as Record<string, unknown> | null;
	if (!d || !text(d.serverId, 256) || !text(d.projectId, 256) || !text(d.versionId, 2048))
		return null;
	return {
		serverId: d.serverId as string,
		projectId: d.projectId as string,
		versionId: d.versionId as string,
		region: text(d.region, 16) ? (d.region as string) : null,
		name: text(d.name, 200) ? (d.name as string) : 'Model'
	};
}

export function parseModelViewerCommand(data: unknown): ModelViewerCommand | null {
	const d = data as Record<string, unknown> | null;
	if (!d || !ACTIONS.has(d.action as string)) return null;
	const ids = Array.isArray(d.db_ids)
		? d.db_ids.filter((id): id is number => Number.isInteger(id) && id > 0).slice(0, 1000)
		: [];
	return {
		action: d.action as ModelViewerCommand['action'],
		db_ids: ids,
		search: text(d.search, 200) ? (d.search as string) : undefined,
		search_property: text(d.search_property, 200) ? (d.search_property as string) : undefined,
		color: typeof d.color === 'string' && /^#[0-9a-fA-F]{6}$/.test(d.color) ? d.color : undefined,
		version_id: text(d.version_id, 2048) ? (d.version_id as string) : undefined
	};
}

/** Recent AI commands in order; every open viewer tab applies the new ones addressed to it. */
export const modelViewerCommands = writable<{ seq: number; command: ModelViewerCommand }[]>([]);
let seq = 0;
// shortcut: keeps the last 20, so a tab still loading after 20 more commands misses the oldest; raise if that happens.
export const sendModelViewerCommand = (command: ModelViewerCommand) =>
	modelViewerCommands.update((list) => [...list, { seq: ++seq, command }].slice(-20));

/** Commands after `lastSeq` addressed to this version, in order, and the new `lastSeq`. */
export function newCommands(
	list: { seq: number; command: ModelViewerCommand }[],
	lastSeq: number,
	versionId: string
) {
	const fresh = list.filter((entry) => entry.seq > lastSeq);
	return {
		commands: fresh
			.map((entry) => entry.command)
			.filter((command) => !command.version_id || command.version_id === versionId),
		lastSeq: fresh.at(-1)?.seq ?? lastSeq
	};
}

export const modelViewerTabId = (ref: ModelViewerRef) =>
	`model-viewer:${ref.serverId}:${ref.versionId}`;

export async function getViewerToken(
	token: string,
	ref: ModelViewerRef,
	signal?: AbortSignal
): Promise<ViewerToken> {
	const response = await fetch(`${WEBUI_API_BASE_URL}/ext/model-viewer/token`, {
		method: 'POST',
		headers: {
			Accept: 'application/json',
			'Content-Type': 'application/json',
			authorization: `Bearer ${token}`
		},
		body: JSON.stringify({
			server_id: ref.serverId,
			project_id: ref.projectId,
			version_id: ref.versionId,
			...(ref.region ? { region: ref.region } : {})
		}),
		cache: 'no-store',
		signal
	});
	const body = await response.json().catch(() => ({}));
	if (!response.ok) throw new Error(body?.detail || 'Model viewer unavailable');
	latest = { token: body as ViewerToken, until: Date.now() + body.expires_in * 1000 };
	return body as ViewerToken;
}

let viewerRuntime: Promise<any> | null = null;
let tokenSource: (() => Promise<ViewerToken>) | null = null;
// The viewer asks for a token right after a tab just fetched one; reuse it instead of another Autodesk refresh.
let latest: { token: ViewerToken; until: number } | null = null;

/** Load Autodesk's viewer once; the token callback asks the most recently opened tab. */
export function loadViewerRuntime(source: () => Promise<ViewerToken>): Promise<any> {
	tokenSource = source;
	viewerRuntime ??= new Promise((resolve, reject) => {
		const css = document.createElement('link');
		css.rel = 'stylesheet';
		css.href = `${VIEWER_BASE}/style.min.css`;
		document.head.appendChild(css);
		const script = document.createElement('script');
		script.src = `${VIEWER_BASE}/viewer3D.min.js`;
		script.onerror = () => reject(new Error('Autodesk viewer failed to load'));
		script.onload = () => {
			const Viewing = (window as any).Autodesk.Viewing;
			// Automatic region routing (v7.109.1+), so no per-region api value.
			Viewing.FeatureFlags?.set?.('DS_ENDPOINTS', true);
			Viewing.Initializer(
				{
					env: 'AutodeskProduction2',
					api: 'streamingV2',
					getAccessToken: (done: (token: string, expires: number) => void) => {
						const left = (latest?.until ?? 0) - Date.now();
						if (latest && left > 60_000)
							return done(latest.token.access_token, Math.floor(left / 1000));
						tokenSource?.()
							.then((t) => done(t.access_token, t.expires_in))
							.catch((error) => console.error('Model viewer token', error));
					}
				},
				() => resolve(Viewing)
			);
		};
		document.head.appendChild(script);
	});
	viewerRuntime.catch(() => (viewerRuntime = null));
	return viewerRuntime;
}

const hexToVector = (THREE: any, hex: string) =>
	new THREE.Vector4(
		parseInt(hex.slice(1, 3), 16) / 255,
		parseInt(hex.slice(3, 5), 16) / 255,
		parseInt(hex.slice(5, 7), 16) / 255,
		1
	);

function resolveIds(viewer: any, command: ModelViewerCommand): Promise<number[]> {
	if (!command.search) return Promise.resolve(command.db_ids ?? []);
	return new Promise((resolve) =>
		viewer.search(
			command.search,
			(ids: number[]) => resolve(ids),
			() => resolve([]),
			command.search_property ? [command.search_property] : undefined
		)
	);
}

/** Apply one AI command; returns how many objects it targeted. */
export async function applyModelViewerCommand(
	viewer: any,
	command: ModelViewerCommand,
	THREE: any = (window as any).THREE
): Promise<number> {
	const ids = await resolveIds(viewer, command);
	// No match: leave the view as it is rather than isolating nothing (which shows everything).
	if (['isolate', 'hide', 'select', 'color'].includes(command.action) && !ids.length) return 0;
	switch (command.action) {
		case 'isolate':
			viewer.isolate(ids);
			viewer.fitToView(ids);
			break;
		case 'hide':
			viewer.hide(ids);
			break;
		case 'show_all':
			viewer.showAll();
			break;
		case 'select':
			viewer.select(ids);
			break;
		case 'clear_selection':
			viewer.clearSelection();
			break;
		case 'fit':
			viewer.fitToView(ids.length ? ids : undefined);
			break;
		case 'color': {
			const color = hexToVector(THREE, command.color ?? '#ff0000');
			for (const id of ids) viewer.setThemingColor(id, color, undefined, true);
			break;
		}
		case 'clear_colors':
			viewer.clearThemingColors();
			break;
		case 'reset_view':
			viewer.clearSelection();
			viewer.clearThemingColors();
			viewer.showAll();
			viewer.fitToView();
			break;
	}
	return ids.length;
}
