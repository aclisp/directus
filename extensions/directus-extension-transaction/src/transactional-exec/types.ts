import type { Accountability } from '@directus/types';

export interface HandlerOptions {
	customAccountability: Accountability | null;
	payload?: Record<string, any> | Record<string, any>[] | string | null;
}
