import { defineEndpoint } from '@directus/extensions-sdk';
import asyncHandler from '@directus/api/utils/async-handler';
import { createHash } from 'node:crypto';

export default defineEndpoint({
	id: 'wechat-offiaccount',
	handler: (router, context) => {
		const { database, services, env, logger } = context;
		//const { ItemsService, UsersService } = services;
		const token = String(env['WECHAT_OFFIACCOUNT_TOKEN']);

		// 接收微信消息和事件
		router.get(
			'/',
			asyncHandler(async (req, res) => {
				// 将token、timestamp、nonce三个参数进行字典序排序
				const tmpArr = [token, req.query.timestamp, req.query.nonce];
				tmpArr.sort();
				// 将三个参数字符串拼接成一个字符串进行sha1加密
				const shasum = createHash('sha1');
				shasum.update(tmpArr.join(''));
				const expectedSignature = shasum.digest('hex');

				// 开发者获得加密后的字符串可与signature对比，标识该请求来源于微信
				if (expectedSignature === req.query.signature) {
					res.send(req.query.echostr);
				} else {
					res.status(400).send('signature error');
				}
			}),
		);
	},
});
