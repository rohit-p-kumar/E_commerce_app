const ErrorHandler = require("../utils/errorhandler");
const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const User = require("../models/userModel");
const sendToken = require("../utils/jwtToken");

//Register A User

exports.registerUser = catchAsyncErrors(async (req,res,next)=>{

    const {name,email,password} = req.body;

    const user = await User.create({
        name,
        email,
        password,
        avatar:{
            public_id:"This is a sample id",
            url:"profilepicUrl"
        },
    });

    sendToken(user,201,res);

    // const token = user.getJWTToken();

    // res.status(201).json({
    //     success:true,
    //     token
    // });
});

// Login User
exports.loginUser = catchAsyncErrors(async (req,res,next)=>{

    const{email,password} = req.body;

    // Checking if user has given password and email both

    if(!email || !password){
        return next(new ErrorHandler("Please Enter Email & Password",400));
    }

    const user = await User.findOne({email}).select("+password");

    if(!user){
        return next(new ErrorHandler("Invalid Email Or Password",401));
    }

    const isPasswordMatched = await user.comparePassword(password);

    
    if(!isPasswordMatched){
        return next(new ErrorHandler("Invalid Email Or Password",401));
    }

    sendToken(user,200,res);
})

// Logout User

exports.logout = catchAsyncErrors(async (req,res,next) => {
   res.cookie("token",null,{
    expires: new Date(Date.now()),
    httpOnly: true
   });

    res.status(200).json({
        success:true,
        message: "Logged Out"
    });
});

// Forgot password
exports.forgotPassword = catchAsyncErrors(async (req,res,next) => {
    const user = await User.findOne({ email: req.body.email });

    if(!user) {
        return next(new ErrorHandler("User Not Found", 404));
    }

    // Get ResetPassword Token
  const resetToken = user.getResetPasswordToken();

  await user.save({validateBeforeSave: false});

  const resetPasswordUrl = `${req.protocol}://${req.get("host")}/api/v1/password/reset/${resetToken}`;
});