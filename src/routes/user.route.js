import { Router } from "express";
import {
    loginUser,
    logoutUser,
    registerUser,
    refreshAccessToken,
    updateAccountDetails,
    getCurrentUser,
    changeCurrentPassword,
    deleteUser,
} from "../controllers/user.controller.js";
import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);

router.route("/login").post(loginUser);

//secured routes
router.route("/logout").get(verifyJwt, logoutUser);

router.route("/refresh-token").get(verifyJwt, refreshAccessToken);

router.route("/change-password").post(verifyJwt, changeCurrentPassword);

router.route("/current-user").get(verifyJwt, getCurrentUser);

router.route("/update-account-details").patch(verifyJwt, updateAccountDetails);

router.route("/delete").delete(verifyJwt, deleteUser);

export default router;
