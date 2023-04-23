import { Request, Response, NextFunction } from 'express';
import passport from "passport";
import dotenv from 'dotenv';
import { Strategy as JWTStrategy, ExtractJwt } from 'passport-jwt';
import jwt from 'jsonwebtoken';
import { User, UserInstance } from '../models/User';

dotenv.config();

const notAuthorizedJson = { status: 401, message: 'Não Autorizado.' };

//Configuração da strategy do passport
/*
passport.use(new BasicStrategy(async (email, password, done) => {
    if (email && password) {
        const user = await User.findOne({
            where: { email, password }
        });

        if (user) {
            return done(null, user)
        }
    }

    return done(notAuthorizedJson, false);
}));

export const privateRoute = (req: Request, res: Response, next: NextFunction) => {
    const authFunction = passport.authenticate('basic', (err: Error, user: UserInstance) => {
        req.user = user;
        return user ? next() : next(notAuthorizedJson);
    });
    authFunction(req, res, next);
}
*/

const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET as string
}

passport.use(new JWTStrategy(options, async (payload, done) => {
    const user = await User.findByPk(payload.id);
    if (user) {
        return done(null, user);
    } else {
        return done(notAuthorizedJson, false);
    }
}));

export const generateToken = (data: object) => {
    return jwt.sign(data, process.env.JWT_SECRET as string);
}

export const privateRoute = (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate('jwt', (err: Error, user: UserInstance) => {
        req.user = user;
        return user ? next() : next(notAuthorizedJson);
    })(req, res, next);
}

export default passport;