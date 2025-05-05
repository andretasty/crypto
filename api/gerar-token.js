// api/gerar-token.js
const crypto = require('crypto');
const axios = require('axios');

module.exports = async (req, res) => {
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

    const { client_id, secret } = req.body;

    if (!client_id || !secret) {
      return res.status(400).json({ error: 'Parâmetros faltando: client_id e secret são obrigatórios' });
    }

    // Gerar timestamp
    const timestamp = Date.now().toString();
    const path = '/v1.0/token?grant_type=1';
    const baseUrl = 'https://openapi.tuyaus.com';

    // Hash vazio para corpo vazio
    const emptyBodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    
    // Montar string para assinatura
    const stringToSign = `GET\n${emptyBodyHash}\n\n${path}`;
    const fullToSign = client_id + timestamp + stringToSign;

    // Gerar assinatura
    const sign = crypto
      .createHmac('sha256', secret)
      .update(fullToSign)
      .digest('hex')
      .toUpperCase();

    // Fazer requisição à API Tuya
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
      success: true,
      access_token: response.data.result.access_token,
      expire_time: response.data.result.expire_time
    });
  } catch (error) {
    console.error('Erro ao obter token:', error);
    
    // Resposta de erro detalhada
    return res.status(500).json({
      success: false,
      error: 'Erro ao obter access_token',
      message: error.message,
      details: error.response?.data || 'Sem detalhes adicionais'
    });
  }
};