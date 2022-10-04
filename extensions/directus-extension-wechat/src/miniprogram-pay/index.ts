import { createDecipheriv, createSign, createVerify, randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { defineEndpoint } from '@directus/extensions-sdk';
import * as x509 from '@peculiar/x509';
import { char32ToUUID, uuidToChar32 } from '../utils/uuid.js';

type AuthorizationHeaderOptions = {
	mchid: string;
	serial_no: string;
	private_key: string;
	method?: string;
	url?: string;
	timestamp?: Date;
	body?: string;
};

type RequestPaymentOptions = {
	appid: string;
	private_key: string;
	timestamp: Date;
	prepay_id: string;
};

type VerifySignatureOptions = {
	logger: any;
	body: any;
	retry?: boolean;
	certsOptions: GetCertificatesOptions;
};

type DecodeCipherObjectOptions = {
	apiv3key: string; // 微信支付APIV3密钥
};

type CipherObject = {
	algorithm: string;
	nonce: string;
	associated_data: string;
	ciphertext: string;
};

type GetCertificatesOptions = {
	host: string;
} & DecodeCipherObjectOptions &
	AuthorizationHeaderOptions;

type Certificate = {
	serial_no: string;
	effective_time: string;
	expire_time: string;
	encrypt_certificate: CipherObject;
	decrypt_certificate: string;
	public_key: string;
};

type FetchAndVerifyOptions = {
	host: string;
	url: string;
	method: string;
	headers: Record<string, string>;
	body: string;
	logger: any;
	certsOptions: GetCertificatesOptions;
	retry?: number;
};

type EndpointError = {
	status?: number; // 微信支付接口返回的HTTP状态码
	request_id?: string; // 微信支付接口应答的HTTP头Request-ID
	error:
		| string // 商户系统(本系统)处理失败的原因
		| {
				// 微信支付接口失败时在消息体返回的错误原因
				code: string; // 详细错误码
				message: string; // 错误描述
				detail: {
					field: string; // 指示错误参数的位置
					value: string; // 错误的值
					issue: string; // 具体错误原因
					location: string;
				};
		  };
};

const asyncHandler = (fn: any) => (req: any, res: any, next: any) => Promise.resolve(fn(req, res, next)).catch(next);

const commonHeaders = {
	Accept: 'application/json',
	'Content-Type': 'application/json',
	'Accept-Language': 'zh-CN',
};

let cacheCertificates: Certificate[] = [];

export default defineEndpoint({
	id: 'wechat-miniprogram-pay',
	handler: (router, context) => {
		const { database, services, env, logger } = context;
		const { ItemsService, UsersService } = services;
		const NOTIFY_ENDPOINTS = ['/create-order-notify'];
		const host: string = String(env['PAY_WECHATMINIPROGRAM_HOST']); // 微信支付的请求域名
		const mchid: string = String(env['PAY_WECHATMINIPROGRAM_MERCHANT_ID']); // 商户号
		const serial_no: string = String(env['PAY_WECHATMINIPROGRAM_SERIAL_NO']); // 商户证书序列号
		const private_key = readEnvFile('PAY_WECHATMINIPROGRAM_PRIVATE_KEY_FILE', env, logger); // 商户私钥
		const apiv3key = String(env['PAY_WECHATMINIPROGRAM_APIV3_KEY']); // APIV3密钥
		const certsOptions = { host, apiv3key, mchid, serial_no, private_key };

		router.use(function (req: any, res, next) {
			if (!req.schema) {
				errorResponse(res, 500, { error: 'no schema' });
				return;
			}

			// 通知接口不需要商户系统(本系统)鉴权
			if (!NOTIFY_ENDPOINTS.includes(req.path) && (!req.accountability || !req.accountability.role)) {
				errorResponse(res, 401, { error: 'authenticate denied' });
				return;
			}

			next();
		});

		router.post(
			'/create-order/:provider(wechatoffiaccount|wechatminiprogram)',
			asyncHandler(async (req: any, res: any) => {
				const serviceOptions = {
					schema: req.schema,
					accountability: req.accountability,
				};

				const orderService = new ItemsService('orders', serviceOptions);
				const userService = new UsersService(serviceOptions);
				const primaryKey = await orderService.createOne(req.body); // 在商户系统(本系统)内创建订单

				try {
					const method = 'POST';
					const url = '/v3/pay/transactions/jsapi';
					const timestamp = new Date();
					const appid = getAppId(env, req);

					// 请求报文主体
					const body = JSON.stringify({
						appid,
						mchid,
						description: req.body.name,
						out_trade_no: uuidToChar32(primaryKey as string),
						time_expire: genTimeExpire(timestamp, 600),
						notify_url: env['PAY_WECHATMINIPROGRAM_NOTIFY_URL'],
						amount: {
							total: req.body.total_price,
						},
						payer: {
							openid: await getOpenId(userService, req),
						},
					});

					const headers = {
						...commonHeaders,
						Authorization: genAuthorizationHeader({ mchid, serial_no, private_key, method, url, timestamp, body }),
					};

					const data = await fetchAndVerify({ host, url, method, headers, body, logger, certsOptions });
					const prepay_id = data.prepay_id;
					// 直接返回 wx.requestPayment 需要的参数
					const request_payment = genRequestPayment({ appid, private_key, timestamp, prepay_id });

					res.send({
						id: primaryKey,
						request_payment,
					});
				} catch (error) {
					// 如果在微信支付下单失败，就删除本系统订单
					await orderService.deleteOne(primaryKey);
					throw error;
				}
			}),
		);

		router.post(
			'/create-order-notify',
			asyncHandler(async (req: any, res: any) => {
				try {
					// 验证签名
					const verify = await verifySignature(req, { logger, body: req.body, certsOptions });

					if (!verify) {
						logger.info('通知回调的签名验证失败');
						res.status(401).send({ code: 'SIGN_ERROR' });
						return;
					}

					// 参数解密
					const decoded = decodeCipherObject(req.body.resource, { apiv3key });
					const { out_trade_no, trade_state, transaction_id } = JSON.parse(decoded);
					const primaryKey = char32ToUUID(out_trade_no);
					logger.info(`收到支付通知 id=${primaryKey} trade_state=${trade_state} wxid=${transaction_id}`);

					// 开启事务
					await database.transaction(async (trx) => {
						const serviceOptions = { schema: req.schema, knex: trx }; // 以 admin 的权限
						const orderService = new ItemsService('orders', serviceOptions);
						const order = await orderService.readOne(primaryKey, { fields: ['status'] });

						if (order.status !== 'success') {
							await orderService.updateOne(primaryKey, { status: trade_state.toLowerCase() });
						}
					});

					// 支付通知接收成功
					res.status(204).end();
				} catch (error) {
					// 支付通知接收失败
					res.status(500).send({ code: String(error).substring(0, 32) });
				}
			}),
		);
	},
});

function genRequestPayment(options: RequestPaymentOptions) {
	const nonce_str = uuidToChar32(randomUUID());
	const timestamp = Math.floor(options.timestamp.getTime() / 1000).toString();
	const package_str = `prepay_id=${options.prepay_id}`;
	const signRequest = [options.appid, timestamp, nonce_str, package_str].join('\n') + '\n';
	const signer = createSign('RSA-SHA256');
	signer.update(signRequest);
	const signature = signer.sign(options.private_key, 'base64');
	return {
		timeStamp: timestamp,
		nonceStr: nonce_str,
		package: package_str,
		signType: 'RSA',
		paySign: signature,
	};
}

/**
 * 生成微信支付的请求签名
 *   https://pay.weixin.qq.com/docs/merchant/development/interface-rules/signature-generation.html
 */
function genAuthorizationHeader(options: AuthorizationHeaderOptions): string {
	const nonce_str = uuidToChar32(randomUUID());
	const { timestamp = new Date() } = options;
	const timestamp_str = Math.floor(timestamp.getTime() / 1000).toString();
	const signRequest = [options.method, options.url, timestamp_str, nonce_str, options.body].join('\n') + '\n';
	const signer = createSign('RSA-SHA256');
	signer.update(signRequest);
	const signature = signer.sign(options.private_key, 'base64');

	const signatureObject = {
		mchid: `"${options.mchid}"`,
		serial_no: `"${options.serial_no}"`,
		nonce_str: `"${nonce_str}"`,
		timestamp: `"${timestamp_str}"`,
		signature: `"${signature}"`,
	};

	const signatureInfo: string[] = [];

	for (const [key, value] of Object.entries(signatureObject)) {
		signatureInfo.push(`${key}=${value}`);
	}

	return `WECHATPAY2-SHA256-RSA2048 ${signatureInfo.join(',')}`;
}

/**
 * 交易结束时间，也就是订单失效时间
 * @param timestamp 当前时间
 * @param timeoutSeconds 当前时间多少秒之后，交易结束
 * @returns 遵循rfc3339标准格式，如 '1975-08-19T15:17:52.000Z'
 */
function genTimeExpire(timestamp: Date, timeoutSeconds: number): string {
	const copy = new Date(timestamp);
	copy.setSeconds(copy.getSeconds() + timeoutSeconds);
	return copy.toISOString();
}

function getAppId(env: Record<string, any>, req: any): string {
	return String(env[`AUTH_${req.params.provider.toUpperCase()}_CLIENT_ID`]);
}

async function getOpenId(userService: any, req: any): Promise<string> {
	const user = await userService.readOne(req.accountability.user, { fields: ['auth_data'] });
	const auth_data = JSON.parse(user.auth_data as string);
	return auth_data[req.params.provider].openid;
}

function errorResponse(res: any, statusCode: number, error: EndpointError) {
	res.status(statusCode).send(error);
}

async function verifySignature(req: any, options: VerifySignatureOptions) {
	const { logger, retry = true, certsOptions } = options;
	let { body } = options;

	if (typeof body !== 'string') {
		body = JSON.stringify(body);
	}

	const signature = req.get('Wechatpay-Signature');
	const serial = req.get('Wechatpay-Serial');
	const timestamp = req.get('Wechatpay-Timestamp');
	const nonce = req.get('Wechatpay-Nonce');

	if (!signature) {
		throw new Error('缺少HTTP头Wechatpay-Signature');
	}

	if (!serial) {
		throw new Error('缺少HTTP头Wechatpay-Serial');
	}

	if (!nonce) {
		throw new Error('缺少HTTP头Wechatpay-Nonce');
	}

	if (!timestamp) {
		throw new Error('缺少HTTP头Wechatpay-Timestamp');
	}

	const timediff = Math.abs(Number(timestamp) - Date.now() / 1000);

	if (Number.isNaN(timediff)) {
		throw new Error('时间戳非数值');
	}

	if (Math.abs(Number(timestamp) - Date.now() / 1000) > 300) {
		throw new Error('时间戳已过期');
	}

	const verifyRequest = [timestamp, nonce, body].join('\n') + '\n';
	const verify = createVerify('RSA-SHA256');
	verify.update(verifyRequest);

	for (const cert of cacheCertificates) {
		if (cert.serial_no === serial) {
			const ok = verify.verify(cert.public_key, signature, 'base64');

			if (!ok) {
				logger.warn(`签名验证失败，签名值=${signature.substring(0, 32)}(截断)`);
			}

			return ok;
		}
	}

	if (retry) {
		logger.info('开始下载微信支付平台证书');
		await getCertificates(certsOptions);
		return await verifySignature(req, { ...options, retry: false });
	}

	throw new Error('微信支付平台证书序列号不相符');
}

function decodeCipherObject(cipher: CipherObject, options: DecodeCipherObjectOptions) {
	const { ciphertext, associated_data, nonce } = cipher;
	const { apiv3key } = options;
	const APIV3_KEY_LENGTH = 16;
	const key_bytes = Buffer.from(apiv3key);
	const nonce_bytes = Buffer.from(nonce);
	const associated_data_bytes = Buffer.from(associated_data);
	const ciphertext_bytes = Buffer.from(ciphertext, 'base64');
	const cipherdata_bytes = ciphertext_bytes.subarray(0, -APIV3_KEY_LENGTH);
	const auth_tag_bytes = ciphertext_bytes.subarray(-APIV3_KEY_LENGTH);
	const decipher = createDecipheriv('aes-256-gcm', key_bytes, nonce_bytes);
	decipher.setAuthTag(auth_tag_bytes);
	decipher.setAAD(associated_data_bytes);

	const output = Buffer.concat([decipher.update(cipherdata_bytes), decipher.final()]);

	return output.toString();
}

async function getCertificates(options: GetCertificatesOptions) {
	const method = 'GET';
	const url = '/v3/certificates';
	const body = '';

	const response = await fetch(options.host + url, {
		method,
		headers: {
			...commonHeaders,
			Authorization: genAuthorizationHeader({ ...options, method, url, body }),
		},
	});

	if (response.status !== 200) {
		throw new Error('下载微信支付平台证书失败');
	}

	const { data } = await response.json();
	const certificates: Certificate[] = data;

	for (const cert of certificates) {
		cert.decrypt_certificate = decodeCipherObject(cert.encrypt_certificate, options);
		const beginIndex = cert.decrypt_certificate.indexOf('-\n');
		const endIndex = cert.decrypt_certificate.indexOf('\n-');
		const str = cert.decrypt_certificate.substring(beginIndex + 2, endIndex);
		const x509Certificate = new x509.X509Certificate(Buffer.from(str, 'base64'));
		const public_key = Buffer.from(x509Certificate.publicKey.rawData).toString('base64');
		cert.public_key = `-----BEGIN PUBLIC KEY-----\n` + public_key + `\n-----END PUBLIC KEY-----`;
	}

	return (cacheCertificates = certificates);
}

/**
 * 发起 HTTP 请求，同时验证应答的签名，通过则返回 HTTP 应答的消息体 JSON，否则抛出异常。
 */
async function fetchAndVerify(options: FetchAndVerifyOptions) {
	const { host, url, method, headers, body, logger, certsOptions, retry = 1 } = options;
	const response = await fetch(host + url, { method, headers, body });
	const status = response.status;

	if (status < 200 || status > 299) {
		const error = await response.text();
		throw new Error(`调用支付接口失败 status=${status} error=${error}`);
	}

	const data = await response.json();
	const ok = await verifySignature(response.headers, { logger, body: data, certsOptions });

	if (ok) {
		return data;
	}

	if (retry > 0) {
		logger.info('应答的签名验证失败，重试！');
		options.retry = retry - 1;
		return await fetchAndVerify(options);
	}

	throw new Error('应答的签名验证失败(重试后)');
}

function readEnvFile(key: string, env: Record<string, any>, logger: any) {
	if (!existsSync(env[key])) {
		return 'undefined';
	}

	try {
		return readFileSync(env[key], { encoding: 'utf8' });
	} catch (error: any) {
		logger.warn(`Can not read file for ${key}: ${error.message}`);
		return 'undefined';
	}
}
