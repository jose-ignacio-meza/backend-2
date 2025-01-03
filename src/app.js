import express from 'express';
import handlebars from 'express-handlebars';
import __dirname from './utils.js';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import mongoose from 'mongoose';
import { Strategy as CustomStrategy } from 'passport-custom';

const app = express();

//Importer los routers
import userRouter from './routes/user.router.js';
import sessionRouter from './routes/session.router.js';

//Configuro cookies y sesiones
const mongoURL = 'mongodb://localhost:27017/CoderHouse70310';

app.use(express.json());
app.use(express.urlencoded({extended : true}));

//Configuramos y conectamos a la base de datos
mongoose.connect(mongoURL)
    .then( () => console.log(''))
    .catch((error) => console.error('Error en conexion:', error))
;

app.use(cookieParser());
app.use(session({
  store: MongoStore.create({
    mongoUrl: mongoURL,
    mongoOptions: { useNewUrlParser: true, useUnifiedTopology: true },
  }),
  secret: 'asd3nc3okasod',
  resave: false,
  saveUninitialized: false
}));

//Configurar nuestro motor de plantilla
app.engine('handlebars', handlebars.engine());
app.set('views', __dirname + '/views');
app.set('view engine','handlebars');


app.use('/', userRouter);
app.use('/api', sessionRouter);

const server = app.listen(8080, ()=> {
    console.log("Listening on PORT 8080")
});