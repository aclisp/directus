import { defineHook } from '@directus/extensions-sdk';
import type { AbstractServiceOptions, File } from '@directus/types';

export default defineHook(({ schedule }, context) => {
	const { logger, database: knex, services, getSchema } = context;
	const { FilesService } = services;

	// 清理没有用到的演员照片和节目音乐
	schedule('*/10 * * * *', async () => {
		const folders = [
			'e4978340-7f2b-40a2-bf6b-7702b2559d74', // 演员照片
			'1f30da68-6aeb-47c2-8bec-0b6834e28159', // 节目音乐
		];

		const hoursAgo = new Date(Date.now() - 8 * 60 * 60 * 1000);

		const filesToDelete = await knex<File>('directus_files')
			.select('id')
			.where('uploaded_on', '<', hoursAgo)
			.whereIn('folder', folders)
			.whereNotExists(function () {
				this.select().from('cat_program').whereRaw('cat_program.music = directus_files.id');
			})
			.whereNotExists(function () {
				this.select().from('cat_performer').whereRaw('cat_performer.photo = directus_files.id');
			})
			.limit(100);

		if (filesToDelete.length == 0) {
			return;
		}

		const serviceOptions: AbstractServiceOptions = {
			schema: await getSchema({ database: knex }),
			knex,
			accountability: null,
		};

		const filesService = new FilesService(serviceOptions);
		const deletedFiles = await filesService.deleteMany(filesToDelete.map((f) => f.id));
		logger.info(`Successfully cleaned up ${deletedFiles.length} orphaned files.`);
	});
});
