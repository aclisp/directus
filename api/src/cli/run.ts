import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { useLogger } from '../logger/index.js';
import { createCli } from './index.js';

const proxy = process.env['http_proxy'] || process.env['HTTP_PROXY'];

if (proxy) {
	const logger = useLogger();
	logger.debug(`Enabling global proxy (${proxy}) for undici...`);
	const proxyAgent = new ProxyAgent(proxy);
	setGlobalDispatcher(proxyAgent);
}

createCli()
	.then((program) => program.parseAsync(process.argv))
	.catch((err) => {
		// eslint-disable-next-line no-console
		console.error(err);
		process.exit(1);
	});
