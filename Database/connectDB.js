import mongoose from "mongoose";


export const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI,{
            dbName:"HybridAuth"
        })
        console.log("Mongodb connected ✅");
        
    } catch (error) {
        console.log("Error to connect with db ❌",error);
        process.exit(1);
        
    }
}