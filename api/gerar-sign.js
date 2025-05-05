import crypto from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { client_id, access_token, secret, payload } = req.body;

  if (!client_id || !access_token || !secret || !payload) {
    return res.status(400).json({ error: 'Parâmetros faltando' });
  }

  const t = Date.now().toString();
  const signStr = client_id + access_token + t + JSON.stringify(payload);

  const sign = crypto
    .createHmac('sha256', secret)
    .update(signStr)
    .digest('hex')
    .toUpperCase();

  return res.status(200).json({ sign, t });
}