import { createHash, randomUUID } from 'node:crypto';
import asyncHandler from '@directus/api/utils/async-handler';
import { defineEndpoint } from '@directus/extensions-sdk';
import { uuidToChar32 } from '../utils/uuid.js';

export default defineEndpoint({
	id: 'wechat-offiaccount',
	handler: (router, context) => {
		const { database, env } = context;
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

		// JS-SDK使用权限签名算法
		router.post(
			'/signature',
			asyncHandler(async (req, res) => {
				const { url } = req.body;
				const noncestr = uuidToChar32(randomUUID());
				const timestamp = Math.floor(Date.now() / 1000);

				const { token: jsapi_ticket } = await database
					.select('token')
					.from('wechat_credentials')
					.where('id', 'wechatoffiaccount-jsapi-ticket')
					.first();

				const data = { jsapi_ticket, noncestr, timestamp, url };

				const strdata = Object.entries(data)
					.map(([key, value]) => `${key}=${value}`)
					.join('&');

				const shasum = createHash('sha1');
				shasum.update(strdata);
				const signature = shasum.digest('hex');

				res.send({
					appId: env['AUTH_WECHATOFFIACCOUNT_CLIENT_ID'],
					timestamp,
					nonceStr: noncestr,
					signature,
				});
			}),
		);
	},
});
