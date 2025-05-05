export default async function handler(req, res) {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  
    const { client_id, access_token, secret, payload } = req.body;
  
    if (!client_id || !access_token || !secret || !payload) {
      return res.status(400).json({ error: 'Faltando dados: client_id, access_token, secret, payload' });
    }
  
    const t = Date.now().toString();
    const signStr = client_id + access_token + t + JSON.stringify(payload);
  
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
  
    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(signStr)
    );
  
    const sign = Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  
    return res.status(200).json({ sign, t });
  }
  