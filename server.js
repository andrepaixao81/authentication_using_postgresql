const express = require('express');
const app = express();
const { pool } = require("./dbConfig");
const bcrypt = require ('bcrypt');
const session = require ('express-session');
const flash = require ('express-flash');
const passport = require('passport');

const initializePassport = require('./passportConfig')

initializePassport(passport)

const PORT = process.env.PORT || 4000;

//renderizador    
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false}));

//sesseion 
app.use(
    session({
        secret: "secret",
        
        resave: false,

        saveUninitialized: false
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

// Rotas
app.get('/',(req,res)=>{
    
    res.render("index");
});

app.get('/users/register', checkAuthenticated ,(req,res)=>{
    
    res.render("register");
});

app.get('/users/login', checkAuthenticated, (req,res)=>{
    
    res.render("login");
});

app.get('/users/dashboard', checkNotAuthenticated, (req,res)=>{
    
    res.render("dashboard", { user: req.user.name });
});

app.get("/users/logout", (req,res, next) => {
    req.logOut((err)=>{
        if (err) {return next (err);}
        req.flash("success_msg", "Você efetuou o logout.");
        res.redirect("/users/login");
    });
    
})

//Realizar cadastro

app.post('/users/register',async(req,res)=>{
    const {name, email, password, password2} = req.body

    console.log({name,email,password,password2});
    const errors = [];
    //Verificar campos vazios
    if(!name || !email || !password || !password2) {
        errors.push({message: "Favor preencher todos os campos."});
    }
    //verificar se a senha contém menos que 6 caracteres
    if (password.length < 6) {
        errors.push ({message: "A senha deve conter no mínino 6 caracteres."})
    }
    // verifica se a confirmação da senha está correta
    if (password != password2) {
        errors.push({message: "As senhas estão diferentes, favor digite novamente."})
    }
    // renderiza para pagina de registro caso encontre algum erro
    if (errors.length > 0) {
        res.render("register",{errors});
    } 
         //Validação se o email já existe no banco de dados
        else {
                
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);
        //Buscando o email no banco de dados
        pool.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log("Resultado do proprietário do e-mail que está tentando se cadastrar!")
                console.log(results.rows)

                if (results.rows.length > 0) {
                    errors.push({message: "O e-mail já se encontra registrado na base de dados."});
                    res.render("register", {errors});
                } else {                    
                    pool.query( 
                        `INSERT INTO users (name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`,
                        [name, email, hashedPassword],
                        (err, results) => {
                            if (err) {
                                throw err;
                            } console.log(results.rows);
                            req.flash("success_msg", "Você conseguiu realizar o registro com sucesso. Por favor, faça o login.");
                            res.redirect("/users/login")
                        }
                    )
                }
            }
        )
    }
});  

// app.update("/users/update", async (req,res)=>{
//     const {password, password2} = req.body

//     const hashedPassword = await bcrypt.hash(password, 10);
//     pool.query(`update users set password = $1 where "id" = id `) [hashedPassword]
// });

// realizar login
app.post("/users/login", 
        passport.authenticate("local", {
        successRedirect: "/users/dashboard",
        failureRedirect: "/users/login",
        failureFlash:true
    })
); 

// verificar se está autenticado
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated() ){
        return res.redirect("/users/dashboard");
    }
    next();
};

function checkNotAuthenticated(req, res, next) {
    if(req.isAuthenticated()) {
        return next();
    }
    res.redirect("/users/login");
};

app.listen(PORT, ()=>{console.log(`Servidor rodando na porta ${PORT}`)});
