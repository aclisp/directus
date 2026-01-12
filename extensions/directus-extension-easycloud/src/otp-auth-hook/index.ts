import { defineHook } from '@directus/extensions-sdk';

export default defineHook(({ schedule }, context) => {
	const { database: knex } = context;

	schedule('11 * * * *', async () => {
		await knex('otp_auth_codes').where('expires_at', '<', new Date()).del();
	});
});
