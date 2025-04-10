import jwt from "jsonwebtoken";
import { User } from "../Models/User.model.js";
import { createAccessToken, createRefreshToken } from "../Utils/tokens.js";
import { Session } from "../Models/Sessions.model.js";

const refreshTokens =async(res,refreshToken) => {
    const decodedId  = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET);
    const currentSession = await Session.findOne({sessionId:decodedId.sessionId});
    //! IF refresh token gets stolen then do this
  
    if (!currentSession) {
        return res.status(401).json({error:"Unauthorized"});
    }
    const user = await User.findById(currentSession.userId).select("-password");
    if (!user) {
        return res.status(401).json({error:"No user found"});
    }
    const newAccessToken = createAccessToken(user._id,currentSession.sessionId);
    const newRefreshToken = createRefreshToken(currentSession.sessionId);
    return {newAccessToken,newRefreshToken,user};
}

export const authenticate =async(req,res,next) => {
    const accessToken = req.cookies.accessToken;
    const refreshToken = req.cookies.refreshToken;
    req.user = null;
    if (!accessToken && !refreshToken) {
        return res.status(401).json({error:"Unauthorized"});
    }
    try {
        if (accessToken) {
            const decodedId = jwt.verify(accessToken,process.env.ACCESS_TOKEN_SECRET);
            const user = await User.findById(decodedId.userId).select("-password");
            if (!user) {
                return res.status(401).json({error:"No user found"});
            }
            req.user = user;
            next();
            return;
        }
        if (!accessToken && refreshToken) {
            const {newAccessToken,newRefreshToken,user} = await refreshTokens(res,refreshToken);
            req.user = user;
            res.cookie("accessToken",newAccessToken,{httpOnly:true,maxAge:15*60*1000});
            res.cookie("refreshToken",newRefreshToken,{httpOnly:true,maxAge:7*24*60*60*1000});
            next();
            return;
        }

    } catch (error) {
        console.log(error);
        return res.status(401).json({error:"Unauthorized"});
        
    }

}
