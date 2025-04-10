import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"

import { Session } from "../Models/Sessions.model.js";
import { User } from "../Models/User.model.js";

import { createAccessToken, createRefreshToken } from "../Utils/tokens.js";

    const createAndSendTokens = async (req, res, user) => {
    const userAgent = req.headers["user-agent"] || "unknown";
    const ip = req.ip || "unknown";
    const session = await Session.create({ userId: user._id, userAgent, ip });
    const accessToken = createAccessToken(user._id, session.sessionId);
    const refreshToken = createRefreshToken(session.sessionId);

    res.cookie("accessToken", accessToken, { httpOnly: true, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

}

export const login = async (req, res) => {
    try {
        if (req.user) {
            return res.redirect("/")
        }
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const isPasswordCorrect =await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ error: "Invalid credentials" });
        }
        user.password = undefined;
        await createAndSendTokens(req, res, user);
        return res.status(200).json({ user, message: "Login successfull" });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
}
export const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: "Name,Email and password are required" });
        }
        const userExits = await User.findOne({ email });
        if (userExits) {
            return res.status(400).json({ error: "User already exists" });
        }
        const hashedPassword =await bcrypt.hash(password, 12);

        const user = await User.create({ name, email,password:hashedPassword });
        user.password = undefined;
        await createAndSendTokens(req, res,user);
        return res.status(201).json({ user, message: "User registered successfully" });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ error: "Internal server error" });
    }
}

export const logout = async(req,res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    const decodedId = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET);
    // ! Deleting session from database
    await Session.findOneAndDelete({sessionId:decodedId.sessionId});
    res.clearCookie("accessToken");
    res.clearCookie("refreshToken");
    return res.status(200).json({ message: "Logout successfull" });
    
}