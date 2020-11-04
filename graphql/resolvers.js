const bcrypt = require('bcryptjs');
const validator = require('validator');

const User = require('../models/user');

module.exports = {
    createUser: async function ({ userInput }, req) {
        const password = userInput.password;
        const email = userInput.email;
        const name = userInput.name;

        const errors = [];
        if (!validator.isEmail(email)) {
            errors.push({ message: 'Invalid e-mail' });
        }
        if (validator.isEmpty(password) || !validator.isLength(password, { min: 5 })) {
            errors.push({ message: 'Too short password' });
        }
        if (errors.length > 0) {
            const error = new Error('Invalid input.');
            error.statusCode = 422;
            error.data = errors;
            throw error;
        }

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            throw new Error('User exists already!');
        }
        const hashedPw = await bcrypt.hash(password, 12);
        const user = new User({
            email: email,
            password: hashedPw,
            name: name
        });
        const createdUser = await user.save();
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    }
};