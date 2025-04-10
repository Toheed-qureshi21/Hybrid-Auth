import express from "express";
import path from "path";
import { login, logout, signup } from "../Controllers/User.controllers.js";
import { authenticate } from "../Middlewares/auth.middleware.js";
import jwt from "jsonwebtoken"
const router = express.Router();

//! GET routes
router.get("/",(req,res)=>{
    res.redirect("/login");
});
router.get("/login",(req,res)=>{
        const token = req?.cookies?.accessToken;
        if (token) {
        const decodedId = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET);
        return res.redirect("/api/home");
        }
       return res.sendFile(path.join(import.meta.dirname,"../public/login.html"));
    
})
router.get("/signup",(req,res)=>{
    res.sendFile(path.join(import.meta.dirname,"../public/signup.html"));
})
router.get("/home",authenticate,(req,res)=>{
    if (!req.user) {
        return res.redirect("/login")
    }
    res.sendFile(path.join(import.meta.dirname,"../public/home.html"));
})

// ! POST routes
router.post("/login",login);
router.post("/signup",signup);
router.post("/logout",authenticate,logout);
export default router;