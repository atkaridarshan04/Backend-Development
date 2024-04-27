import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(`${process.env.MONGO_URI}/${DB_NAME}`);
    console.log(
      `MongoDB connected successfully !! DB HOST: ${conn.connection.host}`
    );
  } catch (error) {
    console.log("MongoDB connection failed ", error);
    process.exit(1);
  }
};

export default connectDB;
