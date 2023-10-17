const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const PORT = process.env.PORT || 3000;
const app = express();
require("dotenv").config();
const bcrypt = require("bcryptjs");
const salt = 10;

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

// Get your secrets and URLs from environment variables
const JWT_SECRET = "vjksjdsjhdsjhdsajhdbsajhdgsahjdbsajhdbsa";
const MONGODB_URL = "mongodb://127.0.0.1:27017/storeme";

// Establish a connection with your MongoDB database
mongoose
  .connect(MONGODB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

// Define a schema for user authentication
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model("users", userSchema);
// --------------------------------------------------------
app.post("/signup", async (req, res) => {
  // Get user data from the request
  const { email, password: plainTextPassword } = req.body;

  // Encrypt the password for storage in the database
  const password = await bcrypt.hash(plainTextPassword, salt);

  try {
    // Store user data in the database
    const response = await User.create({
      email,
      password,
    });
    console.log(response);
    return res.redirect("/");
  } catch (error) {
    console.log(JSON.stringify(error));
    if (error.code === 11000) {
      return res.send({ status: "error", error: "email already exists" });
    }
    throw error;
  }
});
// --------------------------------------------------------------

// Function to verify user login
const verifyUserLogin = async (email, password) => {
  try {
    const user = await User.findOne({ email }).lean();

    if (!user) {
      return { status: "error", error: "user not found" };
    }

    if (await bcrypt.compare(password, user.password)) {
      // Create a JWT token
      const token = jwt.sign(
        {
          id: user._id,
          username: user.email,
          type: "user",
        },
        JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );
      return {
        status: "ok",
        data: token,
      };
    }

    return {
      status: "error",
      error: "invalid password",
    };
  } catch (error) {
    console.log(error);
    return {
      status: "error",
      error: "timed out",
    };
  }
};

// Handle login requests
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Verify user login using the function
  const response = await verifyUserLogin(email, password);

  if (response.status === "ok") {
    // Store the JWT web token as a cookie in the browser
    res.cookie("token", response.data, {
      maxAge: 2 * 60 * 60 * 1000,
      httpOnly: true,
    }); // Max age: 2 hours
    res.redirect("/");
  } else {
    res.json(response);
  }
});

// Function to verify a JWT token
const verifyToken = (token) => {
  try {
    const verify = jwt.verify(token, JWT_SECRET);
    return verify.type === "user";
  } catch (error) {
    console.log(JSON.stringify(error), "error");
    return false;
  }
};

// Handle GET requests
app.get("/", (req, res) => {
  const { token } = req.cookies;
  if (verifyToken(token)) {
    return res.render("home");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  // Clear the JWT token cookie by setting its expiration to a past date
  res.cookie("token", "", { expires: new Date(0), httpOnly: true });
  res.redirect("/login"); // Redirect the user to the login page after logout
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;
  if (verifyToken(token)) {
    // Render the profile editing form
    res.render("profile");
  } else {
    res.redirect("/login");
  }
});

app.post("/profile", async (req, res) => {
  const { token } = req.cookies;
  if (verifyToken(token)) {
    const { email, password: plainTextPassword } = req.body;
    const password = await bcrypt.hash(plainTextPassword, salt);

    try {
      // Update the user's email and password in the database
      const { id } = jwt.verify(token, JWT_SECRET);
      await User.findByIdAndUpdate(id, { email, password });

      // Clear the JWT token cookie
      res.cookie("token", "", { expires: new Date(0), httpOnly: true });
      res.redirect("/login"); // Redirect to the login page after updating the profile
    } catch (error) {
      console.log(JSON.stringify(error));
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("signin");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.listen(PORT, () => {
  console.log(`Running on port ${PORT}`);
});
