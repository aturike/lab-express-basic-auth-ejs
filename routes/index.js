const router = require("express").Router();
const { isLoggedIn } = require("../middleware/route-guard");

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/private", isLoggedIn, (req, res, next) => {
  res.render("private");
});

router.get("/main", (req, res, next) => {
  res.render("main");
});

router.get("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      next(err);
    } else {
      res.render("main", { logOutMessage: "Succesfully logged out" });
    }
  });
});

module.exports = router;
