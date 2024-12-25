import express from 'express';
import User from '../models/user.models.js';
import { createHash , isValidPassword } from '../utils.js'
import jwt from 'jsonwebtoken'
import { cookieExtractor } from '../config/passport.config.js';

const router = express.Router();


router.get('/current/', async (req, res) => {
    try {
        // Extraer el token de las cookies
        const token = cookieExtractor(req);

        if (!token) {
            return res.status(401).send({
                status: false,
                message: 'No se encontró el token en las cookies',
                payload: null
            });
        }

        // Validar el token y obtener el payload
        const decodedToken = jwt.verify(token, 'coderSecret');

        // Respuesta exitosa con los datos validados del token
        return res.status(200).send({
            status: true,
            message: 'Token válido',
            payload: decodedToken
        });
    } catch (error) {
        // Manejo de errores en la validación del token
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).send({
                status: false,
                message: 'El token es inválido',
                payload: null
            });
        } else if (error.name === 'TokenExpiredError') {
            return res.status(401).send({
                status: false,
                message: 'El token ha expirado',
                payload: null
            });
        }

        // Errores inesperados
        return res.status(500).send({
            status: false,
            message: 'Error interno del servidor',
            payload: error.message
        });
    }
});

//Registración
router.post('/register', async (req,res) => {
    try{
        const {first_name, last_name, email, age, rol ,password} = req.body;
        if (!first_name || !last_name || !email || !age|| !rol) 
            return res.status(400).send({ status: false, message: 'All fields are required' });

        let newUser = new User({
            first_name, 
            last_name,
            email, 
            age,
            rol,
            password: createHash(password)
        });

        await newUser.save();
        res.redirect('/login');
    }catch(error){
        console.error('Error al registrar usuario:', error);
        res.status(500).send('Error al registrar usuario');
    }
})

//Iniciar sesión 
router.post('/login', async (req,res) => {
    try{
        const { email, password } = req.body;
        if (!email || !password) 
            return res.status(400).send({ status: "error", message: 'Incomplete values'});

        //No es necesario preguntar por el password desde la base de datos
        const user = await User.findOne({email});
        if(!user){
            return res.status(401).send('Usuario no encontrado');
        }

        if(!isValidPassword(user,password)){
            return res.status(403).send({ status: "error", message: 'Incorrect password'});
        }
        req.session.user = user;
        let token = jwt.sign( {email, role:user.rol}, "coderSecret", { expiresIn : "24h"});
        res.cookie('tokenCookie', token, {httpOnly: true, maxAge:60*60*1000 }).redirect('/perfil');
    }catch(error){
        console.error('Error al iniciar sesión');
        res.status(500).send('Error al iniciar sesión');
    }

})

// router.post('/login', (req, res) => {
//     const { email, password } = req.body;
//     if(email === "coder@coder.com" && password === "password"){
//         let token = jwt.sign( {email, role:"user"}, "coderSecret", { expiresIn : "24h"});
//         res.cookie('tokenCookie', token, {httpOnly: true, maxAge:60*60*1000 }).send({message : "Login exitoso"});
//         res.redirect('/perfil');
//     }else{
//         res.status(401).send({message : "Credenciales inválidas"});
//     }
// });

//Restaurar contraseña
router.post('/restore-password', async (req, res) => {
    const {email, newPassword} = req.body;
    try{
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(400).send({ status: 'error', message: 'User not found' });
        }

        user.password = createHash(newPassword);
        await user.save();

        return res.redirect('/login'); // Redirige a la vista de login

    }catch (error) {
        return res.status(500).send({ status: 'error', message: 'Internal server error' });
    }
})


//Cerrar sesión del usuario
router.post('/logout', (req, res) => {
    req.session.destroy( (error) => {
        if(error){
            console.error('Error al cerrar sesión');
            res.status(500).send('Error al cerrar sesión');
        } else{
            res.redirect('/login');
        }
    })
})

export default router;