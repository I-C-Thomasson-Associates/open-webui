import { WEBUI_API_BASE_URL } from '$lib/constants';

export type UserUsageLimitResponse = {
	percent: number | null;
	tier: string | null;
	month: string;
	reset_at: number;
	exempt: boolean;
};

export const getUserUsageLimit = async (token: string): Promise<UserUsageLimitResponse> => {
	let error = null;

	const res = await fetch(`${WEBUI_API_BASE_URL}/usage/limit`, {
		method: 'GET',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${token}`
		}
	})
		.then(async (res) => {
			if (!res.ok) throw await res.json();
			return res.json();
		})
		.catch((err) => {
			console.error(err);
			error = err.detail ?? err;
			return null;
		});

	if (error) {
		throw error;
	}

	return res;
};
