const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
const User = mongoose.model("User");
//const crypto = require('crypto')
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config/keys");
const requireLogin = require("../middleware/requireLogin");
const nodemailer = require("nodemailer");
const sendgridTransport = require("nodemailer-sendgrid-transport");
const { SENDGRID_API, EMAIL } = require("../config/keys");

//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  API KEY FOR instaclonebyaj GENERATED ON 31AUG, 2020 12:31 PM

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key: SENDGRID_API,
    },
  })
);

router.get("/protected", requireLogin, (req, res) => {
  res.send("hello user");
});

router.post("/signup", (req, res) => {
  /*
    console.log(req.body.name)
    res.send("sign up page")
    */
  const { name, email, password, pic } = req.body;
  if (!email || !password || !name) {
    return res.status(422).json({ error: "please add all the fields" });
  }
  /*
    res.json({message:"successfully posted"})
    */
  User.findOne({ email })
    .then((savedUser) => {
      if (savedUser) {
        return res
          .status(422)
          .json({ error: "user already exists with this email" });
      }
      bcrypt.hash(password, 12).then((hashedpassword) => {
        const user = new User({
          email,
          password: hashedpassword,
          name,
          pic,
        });

        user
          .save()
          .then((user) => {
            transporter.sendMail({
              to: user.email,
              from: "instaclonebyaj001@gmail.com",
              subject: "sigup success",
              html: "<h1>Welcome to instagram</h1>",
            });
            res.json({ message: "saved successfully" });
          })
          .catch((err) => {
            console.log(err);
          });
      });
    })
    .catch((err) => {
      console.log(err);
    });
});

router.post("/signin", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(422).json("please add email or password");
  }
  User.findOne({ email }).then((savedUser) => {
    if (!savedUser) {
      return res.status(422).json({ error: "invalid email or password" });
    }
    bcrypt
      .compare(password, savedUser.password)
      .then((doMatch) => {
        if (doMatch) {
          //res.json("successfully signed in")
          const token = jwt.sign({ _id: savedUser._id }, JWT_SECRET);
          const { _id, name, email, followers, following, pic } = savedUser;
          res.json({
            token,
            user: { _id, name, email, followers, following, pic },
          });
        } else {
          return res.status(422).json({ error: "invalid email or password" });
        }
      })
      .catch((err) => {
        console.log(err);
      });
  });
});

// router.post('/reset-password',(req,res)=>{
//     crypto.randomBytes(32,(err,buffer)=>{
//         if(err){
//             console.log(err)
//         }
//         const token = buffer.toString("hex")
//         //console.log(buffer)
//         User.findOne({email:req.body.email})
//         .then(user=>{
//             if(!user){
//                 return res.status(422).json({error:"user doesn't exist with this email"})
//             }
//             user.resetToken = token
//             user.expireToken = Date.now() + 3600000
//             user.save().then((result)=>{
//                 transporter.sendMail({
//                     to:user.email,
//                     from:"donotreply@insta.com",
//                     subject:"password reset",
//                     html:`
//                     <p>You requested for password reset</p>
//                     <h5><a href="${EMAIL}/reset/${token}">Click here</a> to reset password</h5>
//                     `
//                 })
//                 res.json({message:"check your email"})
//             })
//         })

//     })
// })

// router.post('/new-password',(req,res)=>{
//     const newPassword = req.body.password
//     const sentToken = req.body.token
//     User.findOne({resetToken:sentToken,expireToken:{$gt:Date.now()}})
//     .then(user=>{
//         if(!user){
//             return res.status(422).json({error:"Session Expired, try again !"})
//         }
//         bcrypt.hash(newPassword,12).then(hashedpassword=>{
//             user.password = hashedpassword
//             user.resetToken = undefined
//             user.expireToken = undefined
//             user.save().then((savedUser)=>{
//                 res.json({message:"password updated successfully"})
//             })
//         })
//     }).catch(err=>{
//         console.log(err)
//     })
// })

module.exports = router;
