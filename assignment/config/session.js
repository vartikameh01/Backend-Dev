// config/session.js

import dotenv from "dotenv";
dotenv.config();   

import session from "express-session";
import MongoStore from "connect-mongo";

console.log("SESSION FILE CHECK:", process.env.MONGO_URI); // debug

export const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || "fallbacksecret",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/securityDB"
  }),
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 30
  }
});