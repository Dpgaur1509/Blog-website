import mongoose from "mongoose";
import dotenv from 'dotenv'

dotenv.config();

export const Connection= async () =>{ 
    const URL=`mongodb+srv://user:Dpgaur@blog-app.drzwmya.mongodb.net/?retryWrites=true&w=majority&appName=Blog-app`;
    try {
        await mongoose.connect(URL);
        console.log("MongoDB Connected...");
    } catch (error) {
        console.log("Error in connecting",error);
    }
}

export default Connection;