const router = require("express").Router();
const bcryptjs = require("bcryptjs");
const User = require("../models/User.model");

const pwdRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/;

router.get("/signup", (req, res, next) => {
  res.render("signup", { errorMessage: "" });
});

router.post("/signup", async (req, res, next) => {
  try {
    if (pwdRegex.test(req.body.password)) {
      const salt = await bcryptjs.genSalt(9);
      const passwordHash = bcryptjs.hashSync(req.body.password, salt);

      await User.create({ username: req.body.username, passwordHash });
      res.redirect("/auth/login");
    } else {
      res.render("signup", { errorMessage: "Password not sufficient" });
    }
  } catch (error) {
    console.log(error);
  }
});

router.get("/login", (req, res, next) => {
  res.render("login", { errorMessage: "" });
});

router.post("/login", async (req, res, next) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    console.log(user);
    if (!!user) {
      if (bcryptjs.compareSync(req.body.password, user.passwordHash)) {
        req.session.user = { username: user.username };
        console.log("Succesful log in");
        res.redirect("/private");
      } else {
        res.render("login", { errorMessage: "Invalid password" });
      }
    } else {
      res.render("login", { errorMessage: "Invalid user" });
    }
  } catch (error) {
    console.log(error);
  }
});

module.exports = router;
