const Joi = require("joi");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
var crypto = require("crypto");
const secret = "abc13";
const { signupSchema } = require("./schema");
const express = require("express");
const app = express();
app.use(express.json());
app.listen(3000);
const apiurl = "https://api.requestcatcher.com/test";
const mysql = require("mysql2");
const pool = mysql
  .createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "kaka",
  })
  .promise();

// //to get user by jwt
// app.get("/", verifyUser, async (req, res) => {
//   const username = req.user.username;
//   const [[last]] = await pool.query("select * from  `users` where username=?", [
//     username,
//   ]);
//   console.log(last);

//   res.json({
//     name: last.username,
//     email: last.email,
//     password: last.password,
//     pin: last.pin,
//   });
// });
// app.get("/n", async (req, res) => {
//   const username = req.body.username;
//   const password = req.body.password;

//   const [[last]] = await pool.query("select * from  `users`WHERE username=?", [
//     username,
//   ]);
//   console.log(last.password);
//   const hashpassword = last.password;
//   const isMatch = await bcrypt.compare(password, hashpassword);
//   console.log(isMatch);
//   if (!isMatch) {
//     return res.json({ msg: "Invalid Password" });
//   } else {
//     res.json({
//       data: last,
//       msg: last.password,
//     });
//   }
// });
// app.get("/otp", async (req, res) => {
//   const email = req.body.email;
//   const pin = req.body.pin;

//   const [[last]] = await pool.query("select * from  `users`WHERE email=?", [
//     email,
//   ]);

//   if (pin !== last.pin) {
//     return res.json({ msg: "Invalid PIN" });
//   } else {
//     res.json({
//       msg: pin,
//     });
//   }
// });
app.patch("/updatedpassword", async (req, res) => {
  try {
    const { password, pin } = req.body; //destructured problams
    const hashpassword = await bcrypt.hash(password, 10);

    const [[last]] = await pool.query("select * from  `users`WHERE pin=?", [
      pin,
    ]);
    console.log(last.password);

    if (pin !== last.pin) {
      return res.json({ msg: "Invalid PIN" });
    } else {
      const abc = await pool.query(
        "UPDATE `users` SET `password` = ? WHERE  `pin` = ?",
        [hashpassword, pin]
      );
      res.json({
        msg: "pin is correct so your password updated",
      });
    }
    console.log(hashpassword);
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

app.post("/forgotpassword", async (req, res) => {
  try {
    const email = req.body.email;
    const pin = crypto.randomInt(100000, 999999);
    const [sql] = await pool.query(
      "SELECT COUNT(email) AS emailCount FROM users WHERE email = ?",
      [email]
    );

    const emailCount = sql[0].emailCount;

    if (emailCount > 0) {
      const query = await pool.query(
        "UPDATE `users` SET `pin` = ? WHERE  `email` = ?",
        [pin, email]
      );
      res.json({
        msg: "Use this PIN to reset your password",
        pin: pin,
      });
    } else {
      res.status(404).json({ msg: "Email does not exist" });
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const [[userDetails]] = await pool.query(
      "select * from  `users` WHERE  email=?",
      [email]
    );
    console.log(userDetails.email);
    const passwordcheck = await bcrypt.compare(password, userDetails.password);
    if (passwordcheck && userDetails.email === email) {
      const token = jwt.sign({ email: email }, secret);
      return res.json({ msg: "login success", token: token });
    } else {
      return res.json({ msg: "login failed" });
    }
  } catch (err) {
    console.error("Error during password reset:", err);
    res.status(500).json({ msg: "Internal server error" });
    throw err;
  }
});

app.post("/userregistration", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashpassword = await bcrypt.hash(password, 10);
    const { error, value } = signupSchema.validate(req.body);
    if (error) {
      return res.json({ error: error.message });
    } else {
      const [sql] = await pool.query(
        "SELECT COUNT(email) AS emailCount FROM users WHERE email = ?",
        [email]
      );
      const emailCount = sql[0].emailCount;
      if (emailCount > 0) {
        res.json({ msg: "email already exists" });
      } else {
        const qwerty = await pool.query(
          "INSERT INTO `users`(`username`, `email`, `password`) VALUES (?,?,?)",
          [username, email, hashpassword]
        );
        res.json({ msg: "registration done successfully" });
      }
    }
  } catch (error) {
    console.error("Error during password reset:", error);
    res.status(500).json({ msg: "Internal server error" });
    throw error;
  }
});

app.post("/", async (req, res) => {
  const { title, body } = req.body;
  const { error, val } = postSchema.validate(req.body);
  if (error) {
    return res.send("invalid");
  } else {
    const [qwerty] = await pool.query(
      "INSERT INTO `posts`(title, body) VALUES (?,?)",
      [title, body]
    );
    res.json({
      qwerty,
    });
  }
});
app.post("/webHookData", async (req, res) => {
  const { webHookData } = req.body;
  const { error, value } = webHookSchema.validate(req.body);
  if (error) {
    return res.json({ error: error.message });
  } else {
    const [arr] = await pool.query("select * from webhook_user ");
    const [arr1] = await pool.query(
      "INSERT INTO `webhook_user`(`webHookData`) VALUES (?)",
      [webHookData]
    );

    res.send(arr);
    // console.log(arr);
    axios
      .post(apiurl, arr)
      .then((response) => {
        //   console.log(response.data);
        //   console.log(response.status);
        //   console.log(response.statusText);
        return response.data;
      })
      .catch((error) => {
        console.error(error);
      });
  }
});
function verifyUser(req, res, next) {
  var token = req.headers["authorization"];
  if (!token) {
    return res.send("Access Denied");
  }
  try {
    var verified = token.split(" ")[1];
    verified = jwt.verify(token, secret);
    req.user = verified;
    next();
  } catch (err) {
    res.send("Invalid Token");
  }
}
//Joi schema to validate the object data

// const schema = Joi.object().keys({
//   name: Joi.string().min(3).max(30).required(),
//   email: Joi.string().email().required(),
// });

// const result = Joi.validate(dataToValidate, schema);
// // result.error == null means valid

//..................................................
//....................................................

// const Joi = require("joi");
// const express = require("express");
// const app = express();
// const mysql = require("mysql2");
// const pool = mysql
//   .createPool({
//     host: "localhost",
//     user: "root",
//     password: "",
//     database: "kaka",
//   })
//   .promise();
// app.use(express.json());

// app.post("/", async (req, res) => {
//   // Destructure fields from the request body
//   const { username, email, password } = req.body;

//   // Define the validation schema
//   const schema = Joi.object({
//     username: Joi.string().min(3).max(30).required(),
//     // email: Joi.string().email().required(),
//     // password: Joi.string().min(6).required(), // Add password validation
//   });
//   console.log(schema.username);
//   const result=Joi.validate(schema)
//   console.log(result.username);

//   // Validate the request body
//   const { error } = schema.validate(req.body);
//   if (error) {
//     return res.status(400).send(error.details[0].message);
//   }

//   try {
//     // Insert the new user into the database
//     const result = await pool.query(
//       "INSERT INTO `users`(`username`, `email`, `password`) VALUES (?, ?, ?)",
//       [username, email, password] // Use username and email from the request body
//     );
//     res.status(201).send({ message: "User created successfully" });
//   } catch (err) {
//     console.error(err);
//     res.status(500).send({ message: "Internal server error" });
//   }
// });
// //   const {  password } = req.body;

// //   const schema = Joi.object().keys({
// //     username: Joi.string().min(3).max(30).required(),
// //     email: Joi.string().email().required(),
// //   })=req.body;
// //   const result=Joi.validate(schema)
// //   const qwerty = await pool.query(
// //     "INSERT INTO `users`(`name`, `email`, `password`) VALUES (?,?,?)",
// //     [result.username, result.email, password]
// //   );
// // });

// // Start your server
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });
// //
