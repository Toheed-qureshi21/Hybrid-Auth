import jwt from "jsonwebtoken";
import dotenv from "dotenv"
dotenv.config()
export const createAccessToken =(userId,sessionId) => {
    return jwt.sign({userId,sessionId},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"1m"});
}
export const createRefreshToken  = (sessionId) => {
  return jwt.sign({sessionId},process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"});
}
