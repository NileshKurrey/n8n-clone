import { ApiError } from "../libs/api-error.js";
import { ApiResponse } from "../libs/api-response.js";
import { asyncHandler } from "../libs/asyncHandler.js";
import { db } from "../libs/db.js";
import bcrypt from 'bcrypt'
import { genAccessToken, genRefreshToken, genTempToken  } from "../libs/Tokens.js";
import { emailVerificationMailGenContent, forgotPasswordVerificationMailGenContent, sendMail } from "../libs/mails.js";
import crypto from 'crypto'

//register User
export const registerUser = asyncHandler(async(req, res)=>{
   
    const { name,email,image, password } = req.body
    const existingUser = await db.user.findUnique({
        where: {
            email:email
        }
    })
    if(existingUser){
        res.status(400).json(new ApiResponse(400,"User already exists"));
        throw new ApiError(400, "User already exists",);
    }
    const salt = bcrypt.genSaltSync(10);
   const hashedPassword = bcrypt.hashSync(password, salt);
   const {unHashedToken,hashedToken,tokenExpiry} = await genTempToken();
    const user = await db.user.create({
        data: {
            name,
            email,
            image,
            password: hashedPassword,
            verificationToken: hashedToken,
            verificationTokenExpiry: tokenExpiry
        }
    })
    if(!user){
        res.status(400).json(new ApiResponse(400,"User not created"));
        throw new ApiError(400, "User not created",);
    }
    const verifactionUrl = process.env.URL + `/api/v1/user/verify/${unHashedToken}`
    const mailgenContent = emailVerificationMailGenContent(
        name,
        verifactionUrl
    )
    await sendMail({
        email:user.email,
        subject:"Verify your email address",
        mailGenContent:mailgenContent
    })
    res.status(201).json(new ApiResponse(201,{unHashedToken,user: {
          id: user.id,
          name: user.username,
          email: user.email,
          role: user.role,
          image: user.image,}},"User created successfully"));
})
//verify User
export const verifyUser = asyncHandler(async (req, res) => {
  const { token } = req.params;
  if (!token) {
    console.log("Token required!");
    return res.status(400).json(new ApiError(400, "Token required!"));
  }

  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  const user = await db.user.findFirst({
    where: { verificationToken: hashedToken },
  });
  if (!user) {
    return res.status(401).json(new ApiError(401, "Token not found!"));
  }

  if (user.isVerified) {
    return res
      .status(409)
      .json(new ApiError(409, "User already verified!"));
  }

  const isTokenExpired = user.verificationTokenExpiry < new Date();
  if (isTokenExpired) {
    return res
      .status(403)
      .json(new ApiError(403,"Token expired, please request a new one."));
  }

   await db.user.update({
    where: { id: user.id },
    data: {
      isVerified: true,
      verificationToken: null,
      verificationTokenExpiry: null,
    },
  });

  res.status(200).json(new ApiResponse(200,'', "User verified successfully!"));
});
//resend Verfication token
export const resendVerficationToken = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json(new ApiError(400, "All fileds are required!"));
  }

  const user = await db.user.findUnique({
    where: { email },
  });
  if (!user) {
    return res
      .status(401)
      .json(new ApiError(401, "Invalid email or password"));
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    console.log("Invalid email or password");
    return res.status(401).json({
      success: false,
      message: "Invalid email or password",
    });
  }
  if (user.isVerified) {
    console.log("User already verified!");
    return res
      .status(409)
      .json(new ApiError(409, 'User Already Verified'));
  }

  // generate new token :
  const { unHashedToken, hashedToken, tokenExpiry } =
    await genTempToken();

  // update the database :
 await db.user.update({
    where: { id: user.id },
    data: {
      verificationToken: hashedToken,
      verificationTokenExpiry: new Date(tokenExpiry),
    },
  });


  // send email :
  const verificationUrl = process.env.URL + `/api/v1/user/verify/${unHashedToken}`;
  const mailGenContent = emailVerificationMailGenContent(
    user.name,
    verificationUrl,
  );
  await sendMail({
    email: user.email,
    subject: "Verify your email address",
    mailGenContent,
  });

  res
    .status(201)
    .json(new ApiResponse(201, "Verification email sent successfully!"));
});
//login user
export const login = asyncHandler(async(req, res)=>{
    const {email,password} = req.body
    const user = await db.user.findUnique({
        where: {
            email:email
        }
    })
    if(!user){
        res.status(400).json(new ApiResponse(400,"User not found"));
        throw new ApiError(400, "User not found",);
    }
    const isPasswordCorrect = await bcrypt.compare(password,user.password)
    if(!isPasswordCorrect){
        res.status(400).json(new ApiResponse(400,"Password is incorrect"));
        throw new ApiError(400, "Password is incorrect",);
    }
   const accessToken =  await genAccessToken(user);
   const refreshToken = await genRefreshToken(user) 
  await db.user.update({
    where: { id: user.id },
    data: {
      refreshToken: refreshToken,
      refreshTokenExpiry: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), 
    },
  });

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  });
res.status(200).json(
    new ApiResponse(200, "User Login Successfully!", {
      accessToken,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        image: user.image,
      },
    }),
  );
})

//refresh token
export const refreshAccessToken = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json(new ApiError(401, "Refresh token missing"));
  }

  const user = await db.user.findFirst({
    where: { refreshToken },
  });
  if (
    !user ||
    !user.refreshTokenExpiry ||
    user.refreshTokenExpiry < new Date()
  ) {
    return res
      .status(401)
      .json(new ApiError(401, "Refresh token expired or invalid"));
  }

  const accessToken = await genAccessToken(user);
  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  });

  return res.status(200).json(
    new ApiResponse(200, "New access token generated!", {
      accessToken,
    }),
  );
});

//forget Password
export const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) {
    console.log("All files Are Required!");
    return res.status(400).json(new ApiError(400, "All files Are Required!"));
  }

  const user = await db.user.findUnique({
    where: { email },
  });
  if (!user) {
    console.log("Invalid credentials!");
    return res.status(401).json(new ApiError(401, "Invalid credentials!"));
  }

  const { unHashedToken, hashedToken, tokenExpiry } =
    await genTempToken();

  
  await db.user.update({
    where: { id: user.id },
    data: {
      forgotPasswordEmailisVerified: false,
      forgotPasswordToken: hashedToken,
      forgotPasswordTokenExpiry: new Date(tokenExpiry),
    },
  });

  const verificationUrl = process.env.URL + `api/v1/user/forgot-password-verification/${unHashedToken}`;
  const mailGenContent = forgotPasswordVerificationMailGenContent(
    user.name,
    verificationUrl,
  );
  await sendMail({
    email: user.email,
    subject: "Reset your password",
    mailGenContent,
  });

  res.status(200).json(
    new ApiResponse(
      200,
      "Forgot Password verification email sent successfully in your e-mail address!",
      {
        user: {
          forgotPasswordToken:unHashedToken,
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          image: user.image,
        },
      },
    ),
  );
});

//Veryfy forgot password email
export const verifyYourEmailForNewPassword = asyncHandler(
  async (req, res) => {
    const { forgotPasswordToken } = req.params;
    if (!forgotPasswordToken) {
      console.log("ForgotPasswordToken is required!");
      return res
        .status(401)
        .json(new ApiError(401, "ForgotPasswordToken is required!"));
    }

    const hashedToken = await crypto
      .createHash("sha256")
      .update(forgotPasswordToken)
      .digest("hex");

    const user = await db.user.findFirst({
      where: { forgotPasswordToken: hashedToken },
    });
    if (!user) {
      console.log("ForgotPasswordToken is invalid!");
      return res
        .status(401)
        .json(new ApiError(401, "ForgotPasswordToken is invalide!"));
    }
    const ERROR_MESSAGES = {
      USER_ALREADY_VERIFIED: "User already verified!",
      TOKEN_EXPIRED: "Token expired, please request a new one.",
    };
    if (
      !user.forgotPasswordTokenExpiry ||
      user.forgotPasswordTokenExpiry < new Date()
    ) {
      console.log("Token Expired or missing expiry field!");
      return res
        .status(401)
        .json(new ApiError(401, ERROR_MESSAGES.TOKEN_EXPIRED));
    }

    await db.user.update({
      where: { id: user.id },
      data: {
        forgotPasswordEmailisVerified: true,
      },
    });
    res.redirect(`http://localhost:5173/change-password?token=${forgotPasswordToken}`);

  },
);

//reset Password
export const resetPassword = asyncHandler(async (req, res) => {

  const {password, confirmPassword } = req.body;

  if (!password || !confirmPassword) {
    console.log("All fields are required!");
    return res.status(400).json(new ApiError(400, "All fields are required!"));
  }

  if (password !== confirmPassword) {
    
    return res
      .status(400)
      .json(new ApiError(400, "Both Password should be same!"));
  }

  const { forgotPasswordToken } = req.params;
  if (!forgotPasswordToken) {
    return res.status(401).json(new ApiResponse(401, "Token is required!"));
  }

  const hashedToken = crypto
    .createHash("sha256")
    .update(forgotPasswordToken)
    .digest("hex");

  const user = await db.user.findFirst({
    where: {
      forgotPasswordToken: hashedToken,
      forgotPasswordTokenExpiry: {
        gt: new Date(),
      },
    },
  });
  if (!user) {
    return res
      .status(401)
      .json(new ApiResponse(401, "Invalid or expired token"));
  }
  
  if (!user.forgotPasswordEmailisVerified) {
    return res
      .status(403)
      .json(new ApiResponse(403, "Please verify your email first!"));
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  await db.user.update({
    where: { id: user.id },
    data: {
      forgotPasswordToken: null,
      forgotPasswordTokenExpiry: null,
      password: hashedPassword,
      forgotPasswordEmailisVerified: false,
    },
  });

  return res.status(200).json(
  new ApiResponse(200, "Password changed successfully"));
});
//get User Profile
export const getUser = asyncHandler(async (req, res) => {
  const user = req.user;
  res.status(200).json(
    new ApiResponse(200, {
      
        id: user.id,
        firstname: user.firstname,
        lastname: user.lastname,
        username: user.username,
        email: user.email,
        role: user.role,
        image: user.image,
     
    },"Successfully fetched User Profile!"),
  );
});
//update Profile
export const UpdateProfile = asyncHandler(async (req, res) => {

  const { name, email, image } = req.body;
  const user = req.user;
  await db.user.update({
    where: { id: user.id },
    data: {
      name,
      email,
      image,
    },
  });
  res.status(200).json(new ApiResponse(200,'', "Profile updated successfully!"));
})
//logout
export const logout = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json(new ApiError(401, "Refresh token missing"));
  }

  const user = await db.user.findFirst({
    where: { refreshToken },
  });
  if (
    !user ||
    !user.refreshTokenExpiry ||
    user.refreshTokenExpiry < new Date()
  ) {
    return res
      .status(401)
      .json(new ApiError(401, "Refresh token expired or invalid"));
  }

  await db.user.update({
    where: { id: user.id },
    data: {
      refreshToken: null,
      refreshTokenExpiry: null,
    },
  });

  res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  });

  res.status(200).json(new ApiResponse(200, "User Logout Successfully!"));
});

//delete account
export const deleteProfile = asyncHandler(async (req, res) => {
  const user = req.user;
  if(!user){
    return res.status(401).json(new ApiError(401,'',"User not found"));
  }
  await db.user.delete({
    where: { id: user.id },
  });
   res.clearCookie("accessToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  });
  res.clearCookie("refreshToken", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  });
  res.status(200).json(new ApiResponse(200,'', "Profile deleted successfully!"));
   
})
//Admin Controllers -- Controlled by admin whose roles are admin

//get all users
//get user by id
//update user by id
//make user admin
//delete user by id
