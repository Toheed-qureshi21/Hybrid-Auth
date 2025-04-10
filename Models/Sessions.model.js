import mongoose from "mongoose";
import {v4 as uuid} from "uuid";
const sessionSchema = mongoose.Schema({
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"User",
        required:true,  
    },
    sessionId:{
        type:String,
        unique:true,
        required:true,
        default:uuid
    },
    userAgent: { type: String },
    ip: { type: String },
    createdAt: { type: Date, default: Date.now, expires:7*24*60*60*1000 },  
},{
    timestamps:true,
});

export const Session = mongoose.model("Session",sessionSchema);