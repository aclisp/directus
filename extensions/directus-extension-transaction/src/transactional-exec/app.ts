import { defineOperationApp } from '@directus/extensions-sdk';

export default defineOperationApp({
	id: 'tx-exec',
	name: 'Transactional Exec',
	icon: 'box',
	description: 'Transactional execute operation',
	overview: ({ entrypoint, payload }) => [
		{
			label: 'Entrypoint',
			text: entrypoint,
		},
		{
			label: 'Payload',
			text: payload,
		},
	],
	options: [
		{
			field: 'entrypoint',
			name: 'Entrypoint',
			type: 'string',
			meta: {
				width: 'half',
				interface: 'input',
			},
		},
		{
			field: 'permissions',
			name: '$t:permissions',
			type: 'string',
			schema: {
				default_value: '$trigger',
			},
			meta: {
				width: 'half',
				interface: 'select-dropdown',
				options: {
					choices: [
						{
							text: 'From Trigger',
							value: '$trigger',
						},
						{
							text: 'Public Role',
							value: '$public',
						},
						{
							text: 'Full Access',
							value: '$full',
						},
					],
					allowOther: false,
				},
			},
		},
		{
			field: 'payload',
			name: 'Payload',
			type: 'json',
			meta: {
				width: 'full',
				interface: 'input-code',
				options: {
					language: 'json',
					placeholder: JSON.stringify(
						{
							user: '{{ $accountability.user }}',
							data: '{{ $last }}',
						},
						null,
						2,
					),
					template: JSON.stringify(
						{
							user: '{{ $accountability.user }}',
							data: '{{ $last }}',
						},
						null,
						2,
					),
				},
			},
		},
		{
			field: 'code',
			name: '$t:code',
			type: 'string',
			meta: {
				width: 'full',
				interface: 'input-code',
				options: {
					language: 'javascript',
				},
			},
			schema: {
				default_value: `const f = async function(options, context) {
    // Do something...
    return {};
};
return await f(options, context);`,
			},
		},
	],
});
