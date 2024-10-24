// .ENV
// SUPABASE_URL=
// SUPABASE_KEY=
// PORT=
// JWT_SECRET=

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js'); // Importando o cliente Supabase

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;


// Inicializando o cliente Supabase
const supabaseUrl = process.env.SUPABASE_URL; // URL do Supabase
const supabaseKey = process.env.SUPABASE_KEY; // Chave do Supabase
const supabase = createClient(supabaseUrl, supabaseKey); // Criando a instância do Supabase

// Rota para login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
    });

    if (error) {
        return res.status(401).json({ auth: false, message: error.message });
    }

    res.json({ auth: true, token: data.session.access_token });
});



// Rota protegida
app.get('/protected', (req, res) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(403).json({ auth: false, message: 'Token não fornecido' });
    }

    const token = authHeader.split(' ')[1];
    
    if (!token) {
        const token = localStorage.get('token')
    }


    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(500).json({ auth: false, message: 'Falha na autenticação do token.' });
        }

        // Token é válido, prossiga com a lógica
        res.status(200).json({ auth: true, token: token });

    });    
});

app.post('/login/google', async (req, res) => {
    try {
        const { data, error } = await supabase.auth.signInWithOAuth({
            provider: 'google',
        });

        if (error) {
            return res.status(400).json({ auth: false, message: error.message });
        }

        res.json({ auth: true, redirectUrl: data.url });
    } catch (error) {
        res.status(500).json({ message: 'Erro ao autenticar com o Google', error });
    }
});

app.get('/auth/callback', async (req, res) => {
    
});

// Iniciando o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
