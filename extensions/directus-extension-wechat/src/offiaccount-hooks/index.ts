import { ItemsService } from '@directus/api/services/items';
import { defineHook } from '@directus/extensions-sdk';

export default defineHook(({ schedule }, context) => {
	const { env, logger, services, getSchema } = context;
	const { ItemsService } = services;
	const appid = env['AUTH_WECHATOFFIACCOUNT_CLIENT_ID'];
	const secret = env['AUTH_WECHATOFFIACCOUNT_CLIENT_SECRET'];

	if (!appid || !secret) return;

	/* 每隔4分钟刷新一次，参考
	   https://developers.weixin.qq.com/doc/offiaccount/Basic_Information/getStableAccessToken.html
	   这里需要建一个表 wechat_credentials 用来保存各种凭证，字段有
		   - id         varchar(100) primary key, manual 何种凭证，
		   - token      varchar(512) not null            凭证数据，至少要保留 512 个字符
		   - expires_at integer      null                何时过期的秒时间戳，null值表示不过期
		   凭证的id取值可以是
		   - wechatoffiaccount-access-token 微信公众号接口的access_token
		   - wechatoffiaccount-jsapi-ticket 微信公众号用于调用微信JS接口的临时票据
	*/
	schedule('*/4 * * * *', async () => {
		const serviceOptions = {
			schema: await getSchema(),
			accountability: null, // 以 admin 的权限
		};

		const credentials = new ItemsService('wechat_credentials', serviceOptions);

		const token = await fetchAccessToken(credentials);

		if (token) {
			await fetchJsapiTicket(token, credentials);
		}
	});

	async function fetchAccessToken(credentials: ItemsService): Promise<string | null> {
		const res = await fetch('https://api.weixin.qq.com/cgi-bin/stable_token', {
			method: 'POST',
			body: JSON.stringify({
				grant_type: 'client_credential',
				appid,
				secret,
			}),
		});

		if (res.status < 200 || res.status > 299) {
			logger.warn(`[wechatoffiaccount] can not fetch stable_token: got HTTP ${res.status} ${res.statusText}`);
			return null;
		}

		const data = await res.json();

		if (data.errcode && data.errcode !== 0) {
			logger.warn(`[wechatoffiaccount] can not fetch stable_token: got error ${data.errcode} ${data.errmsg}`);
			return null;
		}

		const { access_token, expires_in } = data;

		await credentials.upsertOne({
			id: 'wechatoffiaccount-access-token',
			token: access_token,
			expires_at: Math.floor(Date.now() / 1000) + expires_in,
		});

		return access_token;
	}

	async function fetchJsapiTicket(token: string, credentials: ItemsService) {
		const res = await fetch(`https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=${token}&type=jsapi`);

		if (res.status < 200 || res.status > 299) {
			logger.warn(`[wechatoffiaccount] can not fetch jsapi_ticket: got HTTP ${res.status} ${res.statusText}`);
			return;
		}

		const data = await res.json();

		if (data.errcode && data.errcode !== 0) {
			logger.warn(`[wechatoffiaccount] can not fetch jsapi_ticket: got error ${data.errcode} ${data.errmsg}`);
			return;
		}

		const { ticket, expires_in } = data;

		await credentials.upsertOne({
			id: 'wechatoffiaccount-jsapi-ticket',
			token: ticket,
			expires_at: Math.floor(Date.now() / 1000) + expires_in,
		});
	}
});
