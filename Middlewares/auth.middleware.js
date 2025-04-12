import jwt from "jsonwebtoken";
import { User } from "../Models/User.model.js";
import { createAccessToken, createRefreshToken } from "../Utils/tokens.js";
import { Session } from "../Models/Sessions.model.js";

const refreshTokens =async(req,res,refreshToken) => {
    const decodedId  = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET);
    const currentSession = await Session.findOne({sessionId:decodedId.sessionId});
    //! IF refresh token gets stolen then do this
    //! 🔐 1. No session → token stolen or tampered
    if (!currentSession) {
        return res.status(401).json({error:"Unauthorized"});
    }
    //! 🔐 2. Check for suspicious activity (IP or User-Agent mismatch)
    const requestedUserIp = req.ip;
    const requestedUserAgent = req.headers["user-agent"];
    if (currentSession.ip !== requestedUserIp || currentSession.userAgent !== requestedUserAgent) {
        await Session.findOneAndDelete({sessionId:decodedId.sessionId});
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        return res.status(401).json({message:"Suspicious activity detected please login again"});
    }
     //! 🔐 3. Session is legit → continue
    const user = await User.findById(currentSession.userId).select("-password");
    if (!user) {
        return res.status(401).json({error:"No user found"});
    }
    const newAccessToken = createAccessToken(user._id,currentSession.sessionId);
    const newRefreshToken = createRefreshToken(currentSession.sessionId);
    return {newAccessToken,newRefreshToken,user};
}

export const authenticate = async (req, res, next) => {
    const accessToken = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;
    req.user = null;

    if (!accessToken && !refreshToken) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        // 1. Try access token
        if (accessToken) {
            try {
                const decodedId = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
                const user = await User.findById(decodedId.userId).select("-password");
                if (!user) return res.status(401).json({ error: "No user found" });

                req.user = user;
                return next();
            } catch (err) {
                // If access token is expired, try refresh
                if (err.name !== "TokenExpiredError") throw err;
            }
        }

        // 2. Try refresh token
        if (refreshToken) {
            const { newAccessToken, newRefreshToken, user } = await refreshTokens(req,res, refreshToken);
            req.user = user;

            res.cookie("accessToken", newAccessToken, {
                httpOnly: true,
                maxAge: 15 * 60 * 1000,
                sameSite: "Strict"
            });
            res.cookie("refreshToken", newRefreshToken, {
                httpOnly: true,
                maxAge: 7 * 24 * 60 * 60 * 1000,
                sameSite: "Strict"
            });

            return next();
        }

        return res.status(401).json({ error: "Unauthorized" });

    } catch (error) {
        console.error("Authentication Error:", error);
        return res.status(401).json({ error: "Unauthorized" });
    }
};

