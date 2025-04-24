import { randomUUID } from 'node:crypto';
import { defineHook } from '@directus/extensions-sdk';
import type { Accountability } from '@directus/types';
import { format } from 'date-fns';
import type { Knex } from 'knex';
import {
	InsufficientStock,
	InsufficientStockDetail,
	InvalidStateTransition,
	RequireTransactionScope,
	ResourceNotFound,
} from '../errors.js';
import { transaction } from '../utils.js';

async function getSequenceNextValue(knex: Knex, sequenceName: string): Promise<string> {
	const nextval = await knex('sequence')
		.returning('value')
		.where({
			name: sequenceName,
		})
		.update({
			value: knex.raw('value + 1'),
			date_updated: new Date(),
		})
		.then((result: any) => result[0]);

	if (!nextval) {
		throw new ResourceNotFound({ resource: 'Sequence' });
	}

	return String(nextval.value); // BigInt
}

export function getOrderNumber(date: Date, sequence: string): string {
	const _date = format(date, 'yyyyMMdd');
	const _serial = sequence.slice(-4).padStart(4, '0');
	return `${_date}${_serial}`;
}

async function getWarehouseIdByStoreId(knex: Knex, storeId: string): Promise<string> {
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

async function performInventoryReservation(
	knex: Knex,
	accountability: Accountability | null,
	orderId: string,
	warehouseId: string,
) {
	if (!knex.isTransaction) {
		throw new RequireTransactionScope({ scenario: 'reserving inventory quantities' });
	}

	const stockSkus = await knex('order_parts as op')
		.join('inventory as i', function () {
			this.on('op.sku', '=', 'i.sku').andOn('i.warehouse', '=', knex.raw('?', [warehouseId]));
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

	const quantitiesToDeduct = await knex('order_parts').select('id', 'sku', 'quantity').where('order', orderId);

	for (const item of quantitiesToDeduct) {
		const inventory = await knex('inventory')
			.returning(['id', 'quantity'])
			.where({ sku: item.sku, warehouse: warehouseId })
			.update({
				quantity: knex.raw('quantity - ?', [item.quantity]),
				date_updated: new Date(),
				user_updated: accountability?.user,
			})
			.then((result: any) => result[0]);

		await knex('inventory_changes').insert({
			id: randomUUID(),
			user_created: accountability?.user,
			date_created: new Date(),
			inventory: inventory.id,
			change_type: 'decreasing',
			before_quantity: inventory.quantity + item.quantity,
			after_quantity: inventory.quantity,
			change_reason: 'sale',
			order_part_id: item.id,
		});
	}
}

async function releaseInventoryReservation(
	knex: Knex,
	accountability: Accountability | null,
	orderId: string,
	warehouseId: string,
) {
	if (!knex.isTransaction) {
		throw new RequireTransactionScope({ scenario: 'releasing inventory quantities' });
	}

	const quantitiesToDeduct = await knex('order_parts').select('id', 'sku', 'quantity').where('order', orderId);

	for (const item of quantitiesToDeduct) {
		const inventory = await knex('inventory')
			.returning(['id', 'quantity'])
			.where({ sku: item.sku, warehouse: warehouseId })
			.update({
				quantity: knex.raw('quantity + ?', [item.quantity]),
				date_updated: new Date(),
				user_updated: accountability?.user,
			})
			.then((result: any) => result[0]);

		await knex('inventory_changes').insert({
			id: randomUUID(),
			user_created: accountability?.user,
			date_created: new Date(),
			inventory: inventory.id,
			change_type: 'increasing',
			before_quantity: inventory.quantity - item.quantity,
			after_quantity: inventory.quantity,
			change_reason: 'sale',
			order_part_id: item.id,
		});
	}
}

type StateTransition = {
	from: string;
	to: string[];
	action?: string;
};

const orderStatusTransitions: StateTransition[] = [
	{ from: 'pending', to: ['processing'], action: 'perform_inventory_reservation' },
	{ from: 'processing', to: ['pending'], action: 'release_inventory_reservation' },
	{ from: 'processing', to: ['completed', 'on_hold'] },
	{ from: 'completed', to: ['processing'] },
	{ from: 'on_hold', to: ['processing'] },
];

function matchStateTransition(transitions: StateTransition[], field: string, from: string, to: string) {
	if (from === to) {
		return undefined;
	}

	for (const transition of transitions) {
		if (transition.from === from && transition.to.includes(to)) {
			return transition.action;
		}
	}

	throw new InvalidStateTransition({ field, from, to });
}

async function getOrderTotals(knex: Knex, orderIds: string[]) {
	const totals = await knex
		.with('ServiceItemSums', (qb) => {
			qb.select(
				knex.raw('"order" AS order_id'), // "order" is a reserved keyword, often quoted
				knex.raw('SUM(COALESCE(subtotal, 0)) AS service_items_total'),
			)
				.from('service_order_items')
				.groupBy('order');
		})
		.with('PartSums', (qb) => {
			qb.select(knex.raw('op."order" AS order_id'), knex.raw('SUM(COALESCE(op.quantity * s.price, 0)) AS parts_total'))
				.from('order_parts AS op')
				.join('sku AS s', 'op.sku', 's.id')
				.groupBy('op.order');
		})
		.select(
			'so.id as order_id',
			'so.order_number',
			knex.raw('COALESCE(sis.service_items_total, 0) AS service_items_total'),
			knex.raw('COALESCE(ps.parts_total, 0) AS parts_total'),
			knex.raw('COALESCE(sis.service_items_total, 0) + COALESCE(ps.parts_total, 0) AS total_order_amount'),
		)
		.from('service_orders as so')
		.leftJoin('ServiceItemSums as sis', 'so.id', 'sis.order_id')
		.leftJoin('PartSums as ps', 'so.id', 'ps.order_id')
		.whereIn('so.id', orderIds);

	return totals;
}

export default defineHook(({ filter, action }, { logger }) => {
	// 必须在 filter 中设置订单号；顺便计算出总价（但总价可以放在 action 中计算）
	filter('service_orders.items.create', async (payload: any, { collection }, { database }) => {
		const sequence = await getSequenceNextValue(database, collection);
		payload.order_number = getOrderNumber(new Date(), sequence);
		payload.total_amount = 0;

		for (const { subtotal } of payload.offerings.create) {
			payload.total_amount += subtotal;
		}

		if (payload.parts) {
			for (const { sku, quantity } of payload.parts.create) {
				const skuRecord = await database('sku').where('id', sku).select('price').first();
				payload.total_amount += skuRecord.price * (quantity ?? 1);
			}
		}

		return payload;
	});

	// 必须在 filter 中检查库存、以及检查状态机；库存不足不让更新
	filter('service_orders.items.update', async (payload: any, { keys }, { database, accountability }) => {
		await transaction(database, logger, async (trx) => {
			for (const key of keys) {
				const order = await trx('service_orders').where('id', key).select('order_status', 'store').first();
				const currentOrderStatus = order.order_status;
				const newOrderStatus = payload.order_status ?? currentOrderStatus;
				const action = matchStateTransition(orderStatusTransitions, 'Order Status', currentOrderStatus, newOrderStatus);

				if (action === 'perform_inventory_reservation') {
					const warehouseId = await getWarehouseIdByStoreId(trx, order.store);
					await performInventoryReservation(trx, accountability, key, warehouseId);
				} else if (action === 'release_inventory_reservation') {
					const warehouseId = await getWarehouseIdByStoreId(trx, order.store);
					await releaseInventoryReservation(trx, accountability, key, warehouseId);
				}
			}
		});
	});

	// 计算总价的 action 用一条 SQL 搞定
	action('service_orders.items.update', async ({ keys }, { database }) => {
		const totals = await getOrderTotals(database, keys);

		for (const { order_id, total_order_amount } of totals) {
			await database('service_orders').where('id', order_id).update({
				total_amount: total_order_amount,
			});
		}
	});

	// 必须在 action 里写入库存变更，因为库存必须先写入
	action('inventory.items.create', async ({ payload, key }, { database: knex, accountability }) => {
		if (payload.quantity == null || payload.quantity <= 0) {
			return;
		}

		await knex('inventory_changes').insert({
			id: randomUUID(),
			user_created: accountability?.user,
			date_created: new Date(),
			inventory: key,
			change_type: 'increasing',
			before_quantity: 0,
			after_quantity: payload.quantity,
			change_reason: 'manual_adjustment',
		});
	});

	// 必须在 filter 里写入库存变更，因为变更前数量要先查出来
	filter('inventory.items.update', async (payload: any, { keys }, { database: knex, accountability }) => {
		if (payload.quantity == null) {
			return;
		}

		await transaction(knex, logger, async (trx) => {
			for (const key of keys) {
				const inventory = await trx('inventory').where('id', key).select('quantity').first();
				const before_quantity = inventory.quantity;
				const after_quantity = payload.quantity;

				if (before_quantity == after_quantity) {
					continue;
				}

				await trx('inventory_changes').insert({
					id: randomUUID(),
					user_created: accountability?.user,
					date_created: new Date(),
					inventory: key,
					change_type: before_quantity < after_quantity ? 'increasing' : 'decreasing',
					before_quantity,
					after_quantity,
					change_reason: 'manual_adjustment',
				});
			}
		});
	});
});
