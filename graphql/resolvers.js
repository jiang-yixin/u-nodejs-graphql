const bcrypt = require('bcryptjs');
const validator = require('validator');
const jwt = require('jsonwebtoken');

const User = require('../models/user');
const Post = require('../models/post');
const { clearImage } = require('../utils/file');

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
    },
    login: async function ({ email, password }) {
        const user = await User.findOne({ email: email });
        if (!user) {
            const error = new Error('User is not found.');
            error.statusCode = 401;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if (!isEqual) {
            const error = new Error('Password is wrong.');
            error.statusCode = 401;
            throw error;
        }
        const token = jwt.sign(
            { email, userId: user._id.toString() },
            'secret',
            { expiresIn: '1h' }
        );

        return { token: token, userId: user._id.toString() };
    },
    createPost: async function ({ postInput }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const title = postInput.title;
        const content = postInput.content;
        const imageUrl = postInput.imageUrl;

        const errors = [];
        if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
            errors.push({ message: 'Too short title' });
        }
        if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
            errors.push({ message: 'Too short content' });
        }
        if (validator.isEmpty(imageUrl)) {
            errors.push({ message: 'Empty imageUrl' });
        }
        if (errors.length > 0) {
            const error = new Error('Invalid input.');
            error.statusCode = 422;
            error.data = errors;
            throw error;
        }

        const user = await User.findById(req.userId);
        if (!user) {
            const error = new Error('Not found user');
            error.statusCode = 401;
            throw error;
        }

        const post = new Post({ title, content, imageUrl, creator: user });
        user.posts.push(post);
        const createdPost = await post.save();
        await user.save();
        return {
            ...createdPost._doc,
            _id: createdPost._id.toString(),
            createdAt: createdPost.createdAt.toISOString(),
            updatedAt: createdPost.updatedAt.toISOString()
        };
    },
    posts: async function ({ page }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }
        if (!page) {
            page = 1;
        }

        const perPage = 2;
        const totalItems = await Post.find().countDocuments();
        const posts = await Post.find().populate('creator').sort({ createdAt: -1 }).skip((page - 1) * perPage).limit(perPage);
        return {
            posts: posts.map(p => {
                return { ...p._doc, _id: p._id.toString(), createdAt: p.createdAt.toISOString(), updatedAt: p.updatedAt.toISOString() }

            }),
            totalItems
        };
    },
    post: async function ({ id }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const post = await Post.findById(id).populate('creator');
        if (!post) {
            const error = new Error('Not found post.');
            error.statusCode = 404;
            throw error;
        }

        return {
            ...post._doc,
            _id: post._id.toString(),
            createdAt: post.createdAt.toISOString(),
            updatedAt: post.updatedAt.toISOString()
        };
    },
    updatePost: async function ({ id, postInput }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const post = await Post.findById(id).populate('creator');
        if (!post) {
            const error = new Error('Not found post.');
            error.statusCode = 404;
            throw error;
        }
        if (post.creator._id.toString() !== req.userId.toString()) {
            const error = new Error('Not authorized.');
            error.statusCode = 403;
            throw error;
        }

        // validation fields
        const title = postInput.title;
        const content = postInput.content;
        const imageUrl = postInput.imageUrl;
        const errors = [];
        if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
            errors.push({ message: 'Too short title' });
        }
        if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
            errors.push({ message: 'Too short content' });
        }
        if (validator.isEmpty(imageUrl)) {
            errors.push({ message: 'Empty imageUrl' });
        }
        if (errors.length > 0) {
            const error = new Error('Invalid input.');
            error.statusCode = 422;
            error.data = errors;
            throw error;
        }

        post.title = title;
        post.content = content;
        if (imageUrl !== 'undefined') {
            post.imageUrl = imageUrl;
        }

        const updatedPost = await post.save();
        return {
            ...updatedPost._doc,
            _id: updatedPost._id.toString(),
            createdAt: updatedPost.createdAt.toISOString(),
            updatedAt: updatedPost.updatedAt.toISOString()
        };
    },
    deletePost: async function ({ id }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const post = await Post.findById(id);
        if (!post) {
            const error = new Error('Not found post.');
            error.statusCode = 404;
            throw error;
        }
        if (post.creator.toString() !== req.userId.toString()) {
            const error = new Error('Not authorized.');
            error.statusCode = 403;
            throw error;
        }

        clearImage(post.imageUrl);
        await Post.findByIdAndRemove(id);
        const user = await User.findById(req.userId);
        user.posts.pull(id);
        await user.save();
        return true;
    },
    user: async function (args, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const user = await User.findById(req.userId.toString());
        if (!user) {
            const error = new Error('Not found user.');
            error.statusCode = 404;
            throw error;
        }

        return {
            ...user._doc,
            id: user._id.toString()
        };
    },
    updateStatus: async function ({ status }, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        const user = await User.findById(req.userId.toString());
        if (!user) {
            const error = new Error('Not found user.');
            error.statusCode = 404;
            throw error;
        }

        user.status = status;
        await user.save();

        return true;
    }
};