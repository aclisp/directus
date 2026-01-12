import { createRateLimiter } from '@directus/api/rate-limiter';
import asyncHandler from '@directus/api/utils/async-handler';
import { getIPFromReq } from '@directus/api/utils/get-ip-from-req';
import { validateEnv } from '@directus/api/utils/validate-env';
import { useEnv } from '@directus/env';
import { HitRateLimitError } from '@directus/errors';
import type { RequestHandler } from 'express';
import type { RateLimiterMemory, RateLimiterRedis } from 'rate-limiter-flexible';

let checkRateLimit: RequestHandler = (_req, _res, next) => next();

export let rateLimiter: RateLimiterRedis | RateLimiterMemory;

const env = useEnv();

if (env['RATE_LIMITER_OTP_AUTH_ENABLED'] === true) {
	validateEnv(['RATE_LIMITER_OTP_AUTH_DURATION', 'RATE_LIMITER_OTP_AUTH_POINTS']);

	rateLimiter = createRateLimiter('RATE_LIMITER_OTP_AUTH');

	checkRateLimit = asyncHandler(async (req, res, next) => {
		const ip = getIPFromReq(req);

		if (ip) {
			try {
				await rateLimiter.consume(ip, 1);
			} catch (rateLimiterRes: any) {
				if (rateLimiterRes instanceof Error) throw rateLimiterRes;

				res.set('Retry-After', String(Math.round(rateLimiterRes.msBeforeNext / 1000)));
				throw new HitRateLimitError({
					limit: +(env['RATE_LIMITER_OTP_AUTH_POINTS'] as string),
					reset: new Date(Date.now() + rateLimiterRes.msBeforeNext),
				});
			}
		}

		next();
	});
}

export default checkRateLimit;
