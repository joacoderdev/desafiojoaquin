import passport from "passport";
import local from "passport-local";
import GitHubStrategy from "passport-github";
import { hashPassword, isValidPass } from "../utils.js";
import { userModel } from "../models/user.model.js";

const LocalStrategy = local.Strategy;

// Variables de clientId y clientSecret, agregar las necesarias para el test

const clientID = '';
const clientSecret = '';

const initializePassport = () => {
    passport.use(
        "login",
        new LocalStrategy(
            {
                usernameField: 'email'

        },
        async (username, password, done) => {

            try {
                const user = await userModel.findOne({email: username});

                if (!user){
                    console.log('User not found');
                    return done(null, false);
                }

                if(!isValidPass(user, password)) {
                    console.log('Invalid password');
                    return done(null, false);
                }

                return done(null, user)
            } catch(err) {
                return done(`Error: ${err}`, false);
            }
        }
        )
    )
};

passport.use(
    'register',
    new LocalStrategy(
        {
            usernameField: "email",
            passReqToCallback: true,
        }, 
        async (req, username, password, done) => {
            const { firstName, email, age, role } = req.body;

            if(!firstName || !email || !age || !password){
                return done('Missing required fields');
            }

            try {
                const user = await userModel.findOne({email: username});

                if(user) {
                    return done('User already exists');
                }


                const newuser = await userModel.create({firstName, email, age, password: hashPassword(password)})

                return done(null, newuser);
            } catch(err) {
                return done(`Error: ${err}`)
            }

        }
    )
)
passport.use(
    'github',
        new GitHubStrategy(
        {
            clientID: clientID,
            clientSecret: clientSecret,
            callbackURL: 'http://localhost:3000/session/githubcallback',
            scope: 'user:email'
        },
        async (accesssToken, refreshToken, profile, done) => {
            try{
                console.log(profile)
                const user = await userModel.findOne({
                    email: profile.emails[0].value,
                });

                let savedUser;

                if (!user) {
                    const [firstName, lastName] = profile._json.name.split(" ");
                    const newUser = {
                        firstName,
                        email: profile.emails[0].value,
                        password: " ",
                        age: 0,
                    }

                    savedUser = await userModel.create(newUser);                    

                    done(null, savedUser);
                } else {
                    done(null, user);
                }               
            } catch (err) {
                done(err);
            }
        }
    )
)

passport.serializeUser((user, done) => {
    done(null, user._id);
})

passport.deserializeUser(async (id, done) => {
    try{
        const user = await userModel.findById(id);
        done(null, user);
    } catch (err) {
        done(err, false);
    }
})

export default initializePassport;