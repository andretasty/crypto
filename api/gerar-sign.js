// api/gerar-sign.js
const crypto = require('crypto');

module.exports = (req, res) => {
  try {
    // Configurar CORS para permitir acesso
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    // Responder imediatamente para requisições OPTIONS (preflight)
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    // Verificar método
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const { client_id, access_token, secret, payload, url, method } = req.body;

    // Validação de campos
    if (!client_id || !access_token || !secret || !url || !method) {
      return res.status(400).json({ 
        success: false,
        error: 'Parâmetros faltando',
        missingParams: {
          client_id: !client_id,
          access_token: !access_token,
          secret: !secret,
          url: !url,
          method: !method
        }
      });
    }

    // Gerar timestamp
    const timestamp = Date.now().toString();
    
    // Preparar o corpo e calcular hash
    const bodyStr = payload ? JSON.stringify(payload) : '';
    const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');

    // Montar string para assinatura
    const stringToSign = `${method}\n${bodyHash}\n\n${url}`;

    // Gerar assinatura
    const signRaw = client_id + access_token + timestamp + stringToSign;
    const sign = crypto.createHmac('sha256', secret).update(signRaw).digest('hex').toUpperCase();

    return res.status(200).json({ 
      success: true,
      sign, 
      t: timestamp 
    });
  } catch (error) {
    console.error('Erro ao gerar assinatura:', error);
    
    // Resposta de erro detalhada
    return res.status(500).json({
      success: false,
      error: 'Erro ao gerar assinatura',
      message: error.message
    });
  }
};