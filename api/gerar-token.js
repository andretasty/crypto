const crypto = require('crypto');
const axios = require('axios');

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { client_id, secret } = req.body;

    if (!client_id || !secret) {
        return res.status(400).json({ error: 'Parâmetros faltando: client_id e secret são obrigatórios.' });
    }

    const timestamp = Date.now().toString();
    const path = '/v1.0/token?grant_type=1';
    const baseUrl = 'https://openapi.tuyaus.com';

    const emptyBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const stringToSign = `GET\n${emptyBodyHash}\n\n${path}`;
    const fullToSign = client_id + timestamp + stringToSign;

    const sign = crypto
        .createHmac('sha256', secret)
        .update(fullToSign)
        .digest('hex')
        .toUpperCase();

    try {
        const response = await axios.get(`${baseUrl}${path}`, {
            headers: {
                'sign_method': 'HMAC-SHA256',
                'client_id': client_id,
                't': timestamp,
                'sign': sign,
                'mode': 'cors',
                'Content-Type': 'application/json'
            }
        });

        return res.status(200).json({
            access_token: response.data.result.access_token,
            expire_time: response.data.result.expire_time
        });
    } catch (error) {
        console.error('Erro detalhado:', error);
        return res.status(500).json({
            error: 'Erro ao obter access_token',
            details: error.response?.data || error.message
        });
    }
}