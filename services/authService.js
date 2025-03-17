const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const { STATUS_CODE } = require("../Helper/enums");

const register = async (userData) => {
  try {
    const existingUser = await User.findOne({ email: userData.email });
    if (existingUser) {
      return {
        code: STATUS_CODE.BAD_REQUEST,
        success: false,
        message: "Email already exists!",
      };
    }

    const saltRounds = 10;
    userData.password = await bcrypt.hash(userData.password, saltRounds);
    const user = await User.create(userData);

    return {
      code: STATUS_CODE.SUCCESS,
      success: true,
      data: { id: user._id, name: user.name, email: user.email },
    };
  } catch (error) {
    return { code: STATUS_CODE.ERROR, success: false, message: error.message };
  }
};

const login = async ({ email, password }) => {
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return {
        code: STATUS_CODE.SUCCESS,
        success: false,
        message: "Wrong email or password!",
      };
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    return {
      code: STATUS_CODE.SUCCESS,
      success: true,
      data: {
        token,
        user: { id: user._id, name: user.name, email: user.email },
      },
    };
  } catch (error) {
    return { code: STATUS_CODE.ERROR, success: false, message: error.message };
  }
};

module.exports = { register, login };
