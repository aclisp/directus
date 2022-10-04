import { InvalidCredentialsError, InvalidPayloadError, InvalidProviderConfigError } from '@directus/errors';
import type { Accountability } from '@directus/types';
import type { AxiosStatic } from 'axios';
import { Router } from 'express';
import { customAlphabet } from 'nanoid';
import { useLogger } from '../../logger/index.js';
import { respond } from '../../middleware/respond.js';
import { createDefaultAccountability } from '../../permissions/utils/create-default-accountability.js';
import { AuthenticationService } from '../../services/authentication.js';
import type { UsersService } from '../../services/users.js';
import type { AuthDriverOptions, User } from '../../types/index.js';
import asyncHandler from '../../utils/async-handler.js';
import { getIPFromReq } from '../../utils/get-ip-from-req.js';
import { getSchema } from '../../utils/get-schema.js';
import { AuthDriver } from '../auth.js';

const nanoid = customAlphabet('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', 10);

// scope为snsapi_userinfo时网页授权返回的用户信息
type UserInfo = {
	nickname: string;
	headimgurl: string;
};

/**
 * 一个最简单的微信公众号登录机制的实现
 * https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html
 */
export class WeChatOffiAccountAuthDriver extends AuthDriver {
	config: Record<string, any>;
	clientId: string;
	clientSecret: string;
	moduleName: string;

	constructor(options: AuthDriverOptions, config: Record<string, any>) {
		super(options, config);

		const { clientId, clientSecret, ...additionalConfig } = config;

		if (!clientId || !clientSecret) {
			throw new InvalidProviderConfigError({ provider: additionalConfig['provider'] });
		}

		this.config = additionalConfig;
		this.clientId = clientId; // 公众号 appId
		this.clientSecret = clientSecret; // 公众号 appSecret
		this.moduleName = 'WeChatOffiAccountAuthDriver';
	}

	async getUserID(payload: Record<string, any>): Promise<string> {
		const logger = useLogger();
		const axios = (await import('axios')).default;

		// code作为换取access_token的票据，每次用户授权带上的code将不一样，code只能使用一次，5分钟未被使用自动过期。
		if (!payload['code']) {
			logger.trace(`[${this.moduleName}] No code in payload`);
			throw new InvalidCredentialsError();
		}

		// 通过code换取网页授权access_token，同时获取到 openid
		const request = {
			baseURL: 'https://api.weixin.qq.com',
			url: '/sns/oauth2/access_token',
			method: 'GET',
			params: {
				appid: this.clientId,
				secret: this.clientSecret,
				code: payload['code'],
				grant_type: 'authorization_code',
			},
		};

		const response = await axios.request(request);
		logger.trace(`[${this.moduleName}] Request ${request.url} response.data : ${JSON.stringify(response.data)}`);
		const { access_token, openid, scope, unionid, errcode = 0, errmsg = '' } = response.data;
		let userInfo: UserInfo | undefined;

		if (errcode != 0) {
			const message = `Request ${request.url} : [${errcode}] ${errmsg}`;
			logger.trace(`[${this.moduleName}] ${message}`);
			throw new InvalidPayloadError({ reason: message });
		}

		if (!openid || !access_token) {
			// openid 和 access_token 必须存在
			logger.warn(`[${this.moduleName}] Failed to find openid or access_token`);
			throw new InvalidCredentialsError();
		}

		if (scope === 'snsapi_userinfo') {
			// 弹出授权页面，则必须有 unionid
			if (!unionid) {
				logger.warn(`[${this.moduleName}] Failed to find unionid for scope ${scope}`);
				throw new InvalidCredentialsError();
			}

			// 拉取用户信息(需scope为snsapi_userinfo)
			userInfo = await this.fetchUserInfo(axios, openid, access_token);
		}

		// 找回数据库里的userId
		const usersService = this.getUsersService(await getSchema());
		const user = await this.fetchUser(usersService, openid, unionid);

		if (user) {
			// 更新用户信息
			if (userInfo) {
				await usersService.updateOne(user.id, {
					avatar_url: userInfo.headimgurl,
					first_name: userInfo.nickname,
				});
			}

			return user.id;
		}

		// 创建新用户
		const userId = await usersService.createOne({
			provider: this.config['provider'],
			external_identifier: unionid, // 用户统一标识
			role: this.config['defaultRoleId'],
			auth_data: JSON.stringify({ wechatoffiaccount: { openid } }), // 用户唯一标识
			avatar_url: userInfo ? userInfo.headimgurl : null,
			first_name: userInfo ? userInfo.nickname : 'OffiAccount',
			last_name: 'User',
			email: nanoid() + '@user.cn',
			email_notifications: false,
		});

		return userId as string;
	}

	verify(_user: User, _password?: string): Promise<void> {
		throw new Error('Method not implemented.');
	}

	override async login(user: User, payload: Record<string, any>): Promise<void> {
		const logger = useLogger();
		logger.debug(`[${this.moduleName}] login with user ${JSON.stringify(user)} payload ${JSON.stringify(payload)}`);
		return;
	}

	override async refresh(user: User): Promise<void> {
		const logger = useLogger();
		logger.debug(`[${this.moduleName}] refresh with user ${JSON.stringify(user)}`);
		return;
	}

	private async fetchUser(usersService: UsersService, openid: string, unionid?: string): Promise<User | undefined> {
		const logger = useLogger();

		// openid is stored as directus_users auth_data.wechatoffiaccount.openid
		// this search needs an index as:
		// CREATE UNIQUE INDEX `directus_users_wechatoffiaccount_openid` ON `directus_users` (
		//     json_extract(`auth_data`, '$.wechatoffiaccount.openid')
		// );
		const user = await this.knex
			.select<User>('id', 'auth_data', 'external_identifier')
			.from<User>('directus_users')
			.whereJsonPath('auth_data', '$.wechatoffiaccount.openid', '=', openid)
			.first();

		if (user && unionid && user.external_identifier !== unionid) {
			// unionid is always the directus_users external_identifier
			const unionUser = await this.knex
				.select<User>('id', 'auth_data', 'provider')
				.from('directus_users')
				.where('external_identifier', unionid)
				.first();

			if (unionUser && unionUser.id !== user.id) {
				logger.warn(
					`[${this.moduleName}] User ${unionUser.id} of provider ${unionUser.provider} has an unionid ${unionid} as the external identifier, but now it is removed.`,
				);

				await usersService.updateOne(unionUser.id, { external_identifier: null });
				// see https://github.com/directus/directus/pull/16501
				await usersService.updateOne(unionUser.id, { auth_data: unionUser.auth_data });
			}

			// update user's external_identifier to unionid
			await usersService.updateOne(user.id, { external_identifier: unionid });

			// see https://github.com/directus/directus/pull/16501
			await usersService.updateOne(user.id, {
				auth_data: JSON.stringify({
					...JSON.parse(user.auth_data as string),
					wechatoffiaccount: { openid },
				}),
			});
		}

		return user;
	}

	private async fetchUserInfo(axios: AxiosStatic, openid: string, access_token: string): Promise<UserInfo> {
		const logger = useLogger();

		const request = {
			baseURL: 'https://api.weixin.qq.com',
			url: '/sns/userinfo',
			method: 'GET',
			params: {
				access_token,
				openid,
				lang: 'zh_CN',
			},
		};

		const response = await axios.request(request);
		logger.trace(`[${this.moduleName}] Request ${request.url} response.data : ${JSON.stringify(response.data)}`);
		const { nickname, headimgurl, errcode = 0, errmsg = '' } = response.data;

		if (errcode != 0) {
			const message = `Request ${request.url} : [${errcode}] ${errmsg}`;
			logger.trace(`[${this.moduleName}] ${message}`);
			throw new InvalidPayloadError({ reason: message });
		}

		return { nickname, headimgurl };
	}
}

export function createWeChatOffiAccountAuthRouter(providerName: string): Router {
	const router = Router();

	router.get(
		'/',
		asyncHandler(async (req, res, next) => {
			const logger = useLogger();

			const accountability: Accountability = createDefaultAccountability({
				ip: getIPFromReq(req),
			});

			const userAgent = req.get('user-agent');
			if (userAgent) accountability.userAgent = userAgent;

			const authenticationService = new AuthenticationService({
				accountability: accountability,
				schema: req.schema,
			});

			if (!req.query['code']) {
				logger.warn(
					`[${providerName}] Couldn't extract the login credentials code from query: ${JSON.stringify(req.query)}`,
				);
			}

			const authResponse = await authenticationService.login(providerName, {
				code: req.query['code'],
			});

			const { accessToken, refreshToken, expires } = authResponse;

			res.locals['payload'] = {
				data: { access_token: accessToken, refresh_token: refreshToken, expires },
			};

			next();
		}),
		respond,
	);

	return router;
}
