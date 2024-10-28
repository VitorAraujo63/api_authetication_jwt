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

        res.status(200).json({ auth: true, token: token });

    });    
});


// Rota para login com o google
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


// Rota para signout
app.post('/signout', async (req, res) => {
    try {
        const { error } = await supabase.auth.signOut();
        if (error) throw error;

        res.status(200).json({ sucess: true, message: 'Logout realizado com sucesso' });
    } catch (error) {
        res.status(500).json({ sucess: false, message: 'Erro ao fazer logout', error: error.message });
    }
});

// Rota informações do usuario
app.get('/user_profile', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Token de autenticação não fornecido' });
        }

        const { data: { user }, error: authError } = await supabase.auth.getUser(token);
        if (authError) throw authError;

        if (!user) return res.status(401).json({ message: 'Usuário não encontrado' });

        const { data: userData, error: userDataError } = await supabase
            .from('users')
            .select('*')
            .eq('id', user.id);

        if (userDataError) throw userDataError;

        // Solução para pegar dados de usuarios com provider unico do google
        if (!userData.length) {
            const fallbackData = {
                id: user.id,
                email: user.email,
                name: user.user_metadata.full_name || user.user_metadata.name,
                avatar_url: user.user_metadata.avatar_url,
                created_at: user.created_at,
            };
            return res.status(200).json([fallbackData]);
        }
        res.status(200).json(userData);
        
    } catch (err) {
        console.error('Erro ao buscar dados do usuário:', err);
        res.status(500).json({ message: 'Erro ao buscar dados do usuário', error: err.message });
    }
});


// Iniciando o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
