import express from "express";
import dotenv from "dotenv"
import cookieParser from "cookie-parser";
import { connectDB } from "./Database/connectDB.js";
import userRoutes from "./Routes/User.routes.js";
dotenv.config();

const app = express();

connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({extended:true}));

app.use("/api",userRoutes);


app.listen(process.env.PORT,()=>{
    console.log(`server is running on port http://localhost:${process.env.PORT}/api/`);
});