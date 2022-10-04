import { defineEndpoint } from '@directus/extensions-sdk';

export default defineEndpoint({
	id: 'demo1',
	handler: async (router, context) => {
		const { database, logger } = context;

		/* We do not create this table anymore.

		if (!(await database.schema.hasTable('ext_demo1'))) {
			await database.schema.createTable('ext_demo1', (table) => {
				table.increments('id');
				table.integer('use_counter');
				table.string('device_name');
				table.datetime('due_to');
				table.timestamp('updated_at');
			});

			logger.debug('Table (ext_demo1) created!!');
		}
		*/

		router.get('/', async (_req, res, next) => {
			try {
				const data = await database.select().from('ext_demo1');
				res.json(data);
			} catch (error) {
				next(error);
			}
		});

		router.post('/update/:id', async (req, res, next) => {
			try {
				const data = await database('ext_demo1')
					.update({
						use_counter: database.raw('?? + 1', 'use_counter'),
					})
					.where({
						id: req.params.id,
					});

				res.json(data);
			} catch (error) {
				next(error);
			}
		});

		router.post('/insert', async (_req, res, next) => {
			try {
				const data = await database('ext_demo1').insert({
					use_counter: 1,
					device_name: 'demo1_inserted',
					due_to: new Date(2023, 5, 1, 11, 11, 11),
					updated_at: new Date(),
				});

				res.json(data);
			} catch (error) {
				next(error);
			}
		});

		// 用于调试支付通知
		router.post('/pay-notify-success', (req, res, next) => {
			try {
				const signature = req.get('Wechatpay-Signature');
				const serial = req.get('Wechatpay-Serial');
				const timestamp = req.get('Wechatpay-Timestamp');
				const nonce = req.get('Wechatpay-Nonce');
				const body = req.body;
				logger.info({ signature, serial, timestamp, nonce, body }, 'Got pay-notify');
				res.status(204).end(); // 接收成功！会真的扣钱！
			} catch (error) {
				next(error);
			}
		});
	},
});
