import { sendFCM } from './utils.js';

export default ({ filter, action }, { env, logger, services }) => {
    const { ItemsService } = services;

    action('inbox.items.create', async (meta, context) => {
        const payload = meta.payload;
        const receiverId = payload.penerima;
        
        if (!receiverId) return;

        try {
            const userDevicesService = new ItemsService('user_devices', {
                schema: context.schema,
                knex: context.database
            });

            // Get tokens for the receiver
            const devices = await userDevicesService.readByQuery({
                filter: {
                    user_id: { _eq: receiverId }
                },
                fields: ['token']
            });

            const tokens = devices.map(d => d.token).filter(t => !!t);

            if (tokens.length === 0) {
                logger.info(`FCM Hook: No registered devices for user ${receiverId}`);
                return;
            }

            logger.info(`FCM Hook: Sending notification to user ${receiverId} (${tokens.length} devices)`);

            await sendFCM(env, {
                tokens,
                title: payload.judul || 'Pesan Baru',
                body: payload.pesan ? payload.pesan.replace(/<[^>]*>?/gm, '') : 'Anda menerima pesan baru.', // Strip HTML for body
                metadata: {
                    inbox_id: meta.key,
                    tipe_pesan: payload.tipe_pesan
                },
                logger
            });

        } catch (error) {
            logger.error(`FCM Hook Error: ${error.message}`);
        }
    });
};
