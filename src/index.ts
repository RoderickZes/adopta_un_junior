import express from "express";
import { Request, Response, NextFunction } from 'express';

const app = express();

function basicAuth(req: Request, res: Response,
            next: NextFunction) {
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        res.status(401).json({ message: 'Missing Authorization Header' });
    }
    const base64Credentials =  req.headers.authorization.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    if (!(username ===  process.env.myuser && password ===  process.env.mypassword)) {
      res.status(401).json({ message: 'Invalid Authentication Credentials' });
    }

    next();
}

app.use(basicAuth);