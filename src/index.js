import dotenv from "dotenv";
import connectDB from "./db/connectDB.js";
import app from "./app.js";

dotenv.config({
  path: "./.env",
});

const PORT = process.env.PORT || 5000;

connectDB()
  .then(() => {
    app
      .listen(PORT, () => {
        console.log(`Server listening on port ${PORT}`);
      })
      .on("error", (error) => {
        console.log("MongoDB connection failed ", error);
      });
  })
  .catch((error) => {
    console.log("MongoDB connection failed ", error);
  });
