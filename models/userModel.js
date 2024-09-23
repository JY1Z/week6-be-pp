const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");

const userSchema = mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone_number: { type: String, required: true },
    gender: { type: String, required: true },
    date_of_birth: { type: Date, required: true },
    membership_status: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

// static signup method
userSchema.statics.signup = async function (
  name,
  email,
  password,
  phone_number,
  gender,
  date_of_birth,
  membership_status
) {
  // validation
  if (!name || !email || !password || !phone_number || !gender || !date_of_birth || !membership_status) {
    throw Error("Please add all fields");
  }
  if (!validator.isEmail(email)) {
    throw Error("Email not valid");
  }
  if (!validator.isStrongPassword(password)) {
    throw Error("Password not strong enough");
  }

  if (!validator.isMobilePhone(phone_number, 'any', { strictMode: true })) {
    throw Error("Phone number not valid");
  }

  // Check if user already exists
  const userExists = await this.findOne({ email });

  if (userExists) {
    throw Error("Email already in use");
  }

  // Hash the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  // Create new user
  const user = await this.create({
    name,
    email,
    password: hashedPassword,
    phone_number,
    gender,
    date_of_birth,
    membership_status,
  });

  return user;
};

// static login method
userSchema.statics.login = async function (email, password) {
  if (!email || !password) {
    throw Error("All fields must be filled");
  }

  const user = await this.findOne({ email });
  if (!user) {
    throw Error("Incorrect email");
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    throw Error("Incorrect password");
  }

  return user;
};

module.exports = mongoose.model("User", userSchema);

// What are these functions (userSchema.statics.signup() and userSchema.statics.login())?
// userSchema.statics.signup() : Validates inputs, hashes the password, and creates a new user.
//userSchema.statics.login(): Verifies user credentials (email and password) and authenticates the user.

// Why are they used?
// Keeps user-related logic within the model, ensuring consistency and maintainability.
// These methods can be used throughout the app whenever user signup or login is required.
// Centralizes sensitive operations like password hashing.

// What are the pros and cons of using this approach?
// Pros: Keeps business logic in the model. Methods can be called across the application. Consistent password handling.
// Cons: Fat models: Models can become large and harder to maintain. Harder to test in isolation. Might not scale well for large applications.

// What alternative approaches are available?
// Service layer: Move the business logic to separate services (e.g., UserService), improving separation of concerns, scalability, and testability.
// Validation Middleware: Use middleware like express-validator for input validation, keeping models focused on database operations.

// Did you need to make any changes to the tour-related functions? Why or why not?
// We don't need to change the tour-related code because only the user ID is required in the tour module, and the user ID hasn't changed.