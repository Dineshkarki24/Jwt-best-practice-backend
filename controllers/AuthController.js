const User = require("../models/user.model");
const Token = require("../models/token.modal");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET,EXPIRE_IN } = process.env;
exports.signup = async (req, res) => {
  try {
    //check if username is already taken:
    let user = await User.findOne({ username: req.body.username });
    if (user) {
      return res.status(400).json({ error: "Username taken." });
    } else {
      //create new user and generate a pair of tokens and send
      user = await new User(req.body).save();
      let accessToken = await user.createAccessToken();
      let refreshToken = await user.createRefreshToken();
return res.status(201).json({ accessToken, refreshToken });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error!" });
  }
};
exports.login = async (req, res) => {
  try {
    //check if user exists in database:
    //   console.log(req.body.username,'hshsh')
      let user = await User.findOne({ username: req.body.username });
      console.log(user)
    //send error if no user found:
    if (!user) {
      return res.status(404).json({ error: "No user found!" });
    } else {
      //check if password is valid:
        let valid = await bcrypt.compare(req.body.password, user.password);
        console.log(valid)
      if (valid) {
        //generate a pair of tokens if valid and send
        let accessToken = await user.createAccessToken();
        console.log(accessToken)
          let refreshToken = await user.createRefreshToken();
          console.log(refreshToken)
     res.cookie('refreshToken', refreshToken, {
            expires: new Date(Date.now() + EXPIRE_IN),
    secure: false, // set to true if your using https
    httpOnly: true,
});

return res.status(201).json({ accessToken, refreshToken });
      } else {
        //send error if password is invalid
        return res.status(401).json({ error: "Invalid password!" });
      }
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error!" });
  }
};
exports.generateRefreshToken = async (req, res) => {
  try {
    //get refreshToken
    const  refreshToken  = req.body.refreshToken || req.headers.cookie.split('=')[1];
    console.log(req.headers.cookie.split('=')[1])
    console.log(refreshToken)
    //send error if no refreshToken is sent
    if (!refreshToken) {
      return res.status(403).json({ error: "Access denied,token missing!" });
    } else {
      //query for the token to check if it is valid:
      const tokenDoc = await Token.findOne({ token: refreshToken });
      //send error if no token found:
      if (!tokenDoc) {
        return res.status(401).json({ error: "Token expired!" });
      } else {
        //extract payload from refresh token and generate a new access token and send it
          const payload = jwt.verify(tokenDoc.token, REFRESH_TOKEN_SECRET);
          console.log(ACCESS_TOKEN_SECRET)
        const accessToken = jwt.sign({ user: payload }, ACCESS_TOKEN_SECRET, {
          expiresIn: "10m",
        });
        return res.status(200).json({ accessToken });
      }
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error!" });
  }
};
exports.logout = async (req, res) => {
  try {
    //delete the refresh token saved in database:
    const { refreshToken } = req.body;
    await Token.findOneAndDelete({ token: refreshToken });
    return res.status(200).json({ success: "User logged out!" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error!" });
  }
};