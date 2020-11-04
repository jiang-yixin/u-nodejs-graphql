const User = require('../models/user');
const { validationResult } = require('express-validator/check');

exports.getStatus = async (req, res, next) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            const error = new Error('Failed to find the user');
            error.statusCode = 404;
            throw error;
        }

        res.status(200).json({ message: 'Get status sucessfully', status: user.status });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};

exports.updateStatus = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed');
        error.statusCode = 422;
        throw error;
    }

    const status = req.body.status;

    try {
        const user = await User.findById(req.userId);
        if (!user) {
            const error = new Error('Failed to find the user');
            error.statusCode = 404;
            throw error;
        }

        user.status = status;
        await user.save();
        res.status(200).json({ message: 'User status is updated.', status: user.status });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};
