import type { Request } from 'express';
import { InvalidCredentialsError } from '@directus/errors';

export function ensureAuthenticated(req: Request): asserts req is Request & { accountability: { role: string } } {
	if (!req.accountability || !req.accountability.role) {
		throw new InvalidCredentialsError();
	}
}
