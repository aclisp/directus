import { InvalidCredentialsError } from '@directus/errors';
import { isObject } from '@directus/utils';
import type { Request } from 'express';
import type { Knex } from 'knex';
import type { Logger } from 'pino';

export function ensureAuthenticated(req: Request): asserts req is Request & { accountability: { role: string } } {
	if (!req.accountability || !req.accountability.role) {
		throw new InvalidCredentialsError();
	}
}

/**
 * Execute the given handler within the current transaction or a newly created one
 * if the current knex state isn't a transaction yet.
 *
 * Can be used to ensure the handler is run within a transaction,
 * while preventing nested transactions.
 */
export const transaction = async <T = unknown>(
	knex: Knex,
	logger: Logger,
	handler: (knex: Knex) => Promise<T>,
): Promise<T> => {
	if (knex.isTransaction) {
		return handler(knex);
	} else {
		try {
			return await knex.transaction((trx) => handler(trx));
		} catch (error) {
			if (!shouldRetryTransaction(error)) throw error;

			const MAX_ATTEMPTS = 3;
			const BASE_DELAY = 100;

			for (let attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
				const delay = 2 ** attempt * BASE_DELAY;

				await new Promise((resolve) => setTimeout(resolve, delay));

				logger.trace(`Restarting failed transaction (attempt ${attempt + 1}/${MAX_ATTEMPTS})`);

				try {
					return await knex.transaction((trx) => handler(trx));
				} catch (error) {
					if (!shouldRetryTransaction(error)) throw error;
				}
			}

			/** Initial execution + additional attempts */
			const attempts = 1 + MAX_ATTEMPTS;
			throw new Error(`Transaction failed after ${attempts} attempts`, { cause: error });
		}
	}
};

function shouldRetryTransaction(error: unknown): boolean {
	/**
	 * SQLITE_BUSY is an error code returned by SQLite when an operation can't be
	 * performed due to a locked database file. This often arises due to multiple
	 * processes trying to simultaneously access the database, causing potential
	 * data inconsistencies. There are a few mechanisms to handle this case,
	 * one of which is to retry the complete transaction again
	 * on client-side after a short delay.
	 *
	 * @link https://www.sqlite.org/rescode.html#busy
	 */
	const SQLITE_BUSY_ERROR_CODE = 'SQLITE_BUSY';

	return isObject(error) && error['code'] === SQLITE_BUSY_ERROR_CODE;
}
