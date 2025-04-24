import { randomUUID } from 'node:crypto';
import asyncHandler from '@directus/api/utils/async-handler';
import { defineEndpoint } from '@directus/extensions-sdk';
import type { Knex } from 'knex';
import { IncorrectOrderStatus, InsufficientStock, InsufficientStockDetail, ResourceNotFound } from '../errors.js';
import { ensureAuthenticated } from '../utils.js';

async function getWarehouseIdByOrderId(knex: Knex, orderId: string | undefined): Promise<string> {
	// 检查订单是否存在
	const order = await knex('service_orders').where('id', orderId).select('store').first();

	if (!order) {
		throw new ResourceNotFound({ resource: 'Order' });
	}

	// 获取订单的门店 ID
	const storeId = order.store;

	// 获取与门店关联的第一个仓库 ID
	const storeWarehouse = await knex('store_warehouse')
		.where('store', storeId)
		.orderBy('sort', 'asc') // 假设 sort 列用于排序仓库
		.select('warehouse')
		.first();

	if (!storeWarehouse) {
		throw new ResourceNotFound({ resource: 'Warehouse' });
	}

	return storeWarehouse.warehouse as string;
}

export default defineEndpoint((router, { database }) => {
	// 用于测试
	router.get('/hello', (_req, res) => res.send('Hello, GOLDEN SANDS AUTO CARE'));

	// 获取序列号
	router.get(
		'/sequence/:name/nextval',
		asyncHandler(async (req, res) => {
			ensureAuthenticated(req);

			const nextval = await database('sequence')
				.returning('value')
				.where({
					name: req.params.name,
				})
				.update({
					value: database.raw('value + 1'),
					date_updated: new Date(),
				})
				.then((result: any) => result[0]);

			if (!nextval) {
				throw new ResourceNotFound({ resource: 'Sequence' });
			}

			res.send({ nextval: nextval.value });
		}),
	);

	// 确认订单，保留库存
	router.post(
		'/service_orders/:id/confirm_reservation',
		asyncHandler(async (req, res) => {
			ensureAuthenticated(req);

			const orderId = req.params.id;
			const warehouseId = await getWarehouseIdByOrderId(database, orderId);

			// 使用 FOR UPDATE 锁定相关行，以检查库存是否足够
			await database.transaction(async (trx) => {
				const orderStatus = await trx('service_orders')
					.where('id', orderId)
					.select('order_status')
					.first()
					.forUpdate()
					.then((result) => result.order_status);

				if (orderStatus != 'pending') {
					throw new IncorrectOrderStatus({ expecting_status: 'pending', current_status: orderStatus });
				}

				const stockSkus = await trx('order_parts as op')
					.join('inventory as i', function () {
						this.on('op.sku', '=', 'i.sku').andOn('i.warehouse', '=', trx.raw('?', [warehouseId]));
					})
					.where('op.order', orderId)
					.select('op.sku as sku', 'op.quantity as demand', 'i.quantity as supply')
					.forUpdate();

				const insufficientStockSkus: InsufficientStockDetail[] = [];

				for (const item of stockSkus) {
					if (item.demand > item.supply) {
						insufficientStockSkus.push(item);
					}
				}

				if (insufficientStockSkus.length > 0) {
					throw new InsufficientStock(insufficientStockSkus);
				}

				const quantitiesToDeduct = await trx('order_parts').select('sku', 'quantity').where('order', orderId);

				for (const item of quantitiesToDeduct) {
					const inventory = await trx('inventory')
						.returning(['id', 'quantity'])
						.where({ sku: item.sku, warehouse: warehouseId })
						.update({
							quantity: trx.raw('quantity - ?', [item.quantity]),
							date_updated: new Date(),
							user_updated: req.accountability.user,
						})
						.then((result: any) => result[0]);

					await trx('inventory_changes').insert({
						id: randomUUID(),
						user_created: req.accountability.user,
						date_created: new Date(),
						inventory: inventory.id,
						change_type: 'decreasing',
						before_quantity: inventory.quantity + item.quantity,
						after_quantity: inventory.quantity,
					});
				}

				await trx('service_orders').where('id', orderId).update({
					order_status: 'processing',
					date_updated: new Date(),
					user_updated: req.accountability.user,
				});
			});

			res.status(204).end();
		}),
	);

	// 释放库存
	router.post(
		'/service_orders/:id/release_reservation',
		asyncHandler(async (req, res) => {
			ensureAuthenticated(req);

			const orderId = req.params.id;
			const warehouseId = await getWarehouseIdByOrderId(database, orderId);

			await database.transaction(async (trx) => {
				const orderStatus = await trx('service_orders')
					.where('id', orderId)
					.select('order_status')
					.first()
					.forUpdate()
					.then((result) => result.order_status);

				if (orderStatus != 'processing') {
					throw new IncorrectOrderStatus({ expecting_status: 'processing', current_status: orderStatus });
				}

				const quantitiesToDeduct = await trx('order_parts').select('sku', 'quantity').where('order', orderId);

				for (const item of quantitiesToDeduct) {
					const inventory = await trx('inventory')
						.returning(['id', 'quantity'])
						.where({ sku: item.sku, warehouse: warehouseId })
						.update({
							quantity: trx.raw('quantity + ?', [item.quantity]),
							date_updated: new Date(),
							user_updated: req.accountability.user,
						})
						.then((result: any) => result[0]);

					await trx('inventory_changes').insert({
						id: randomUUID(),
						user_created: req.accountability.user,
						date_created: new Date(),
						inventory: inventory.id,
						change_type: 'increasing',
						before_quantity: inventory.quantity - item.quantity,
						after_quantity: inventory.quantity,
					});
				}

				await trx('service_orders').where('id', orderId).update({
					order_status: 'pending',
					date_updated: new Date(),
					user_updated: req.accountability.user,
				});
			});

			res.status(204).end();
		}),
	);
});
