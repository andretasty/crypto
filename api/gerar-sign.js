import crypto from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { client_id, access_token, secret, payload, url, method } = req.body;

  if (!client_id || !access_token || !secret || !payload || !url || !method) {
    return res.status(400).json({ error: 'Faltando dados: client_id, access_token, secret, payload, url, method' });
  }

  const timestamp = Date.now().toString();
  const bodyStr = JSON.stringify(payload);

  // Hash do corpo
  const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');

  // Monta o stringToSign
  const stringToSign = `${method}\n${bodyHash}\n\n${url}`;

  // Concatena para gerar o sign
  const signRaw = client_id + access_token + timestamp + stringToSign;
  const sign = crypto.createHmac('sha256', secret).update(signRaw).digest('hex').toUpperCase();

  return res.status(200).json({ sign, t: timestamp });
}
