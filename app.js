require('dotenv').config({path:'./config.env'});
const express = require("express");
const bodyparser = require("body-parser");
const mongoose = require("mongoose");
const cors = require('cors');
const api = require("./routes");
//initialize express app
const app = express();
var corsOptions = {
  origin: 'http://localhost:3000',
  optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
  credentials:true,
}
app.use(bodyparser.json());
app.use(cors(corsOptions));
app.use(bodyparser.urlencoded({ extended: false }));
//setup database connection
mongoose.connect("mongodb://localhost:27017/authdemo", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
}).then(() => console.log("Database connected!"))
  .catch((err) => console.error(err));
//setup routes:
app.get("/", (req, res) => {
return res.status(200).send("ok");
});
app.use("/api", api);
//start server and listen on port 4000
app.listen(4000, () => console.log("Server Running on port 4000"));