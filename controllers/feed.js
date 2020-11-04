const path = require('path');
const fs = require('fs');
const { validationResult } = require('express-validator/check');

const Post = require('../models/post');
const User = require('../models/user');
const io = require('../socket');

exports.getPosts = async (req, res, next) => {
    const currentPage = req.query.page || 1;
    const perPage = 2;

    try {
        const totalItems = await Post.find().countDocuments();
        const posts = await Post
            .find()
            .populate('creator')
            .sort({ createdAt: -1 })
            .skip((currentPage - 1) * perPage)
            .limit(perPage);
        res.status(200).json({ message: 'getPosts OK', posts, totalItems });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};

exports.createPost = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed');
        error.statusCode = 422;
        throw error;
    }

    if (!req.file) {
        const error = new Error('No image provided');
        error.statusCode = 422;
        throw error;
    }

    const imageUrl = req.file.path;
    const title = req.body.title;
    const content = req.body.content;

    const post = new Post({
        title,
        imageUrl,
        content,
        creator: req.userId,
    });

    try {
        await post.save();
        const user = await User.findById(req.userId);
        user.posts.push(post);
        await user.save();
        io.getIO().emit(
            'posts',
            { action: 'create', post: { ...post._doc, creator: { _id: req.userId, name: user.name } } }
        );
        res.status(201).json({
            message: "Create post successfully.",
            post,
            creator: { _id: user._id, name: user.name }
        });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
}

exports.getPost = async (req, res, next) => {
    const postId = req.params.postId;
    try {
        const post = await Post.findById(postId)
        if (!post) {
            const error = new Error(`Failed to get post with id ${postId}`);
            error.statusCode = 404;
            throw error;
        }
        res.status(200).json({ message: 'getPost OK', post });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};

exports.updatePost = async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed');
        error.statusCode = 422;
        throw error;
    }

    const postId = req.params.postId;
    const title = req.body.title;
    const content = req.body.content;
    let imageUrl = req.body.image; // old image

    if (req.file) {
        // new image
        imageUrl = req.file.path;
    }

    if (!imageUrl || imageUrl === undefined) {
        const error = new Error('No image provided');
        error.statusCode = 422;
        throw error;
    }

    try {
        const post = await Post.findById(postId).populate('creator');
        if (!post) {
            const error = new Error('No post founded');
            error.statusCode = 404;
            throw error;
        }

        if (post.creator._id.toString() !== req.userId) {
            const error = new Error('Not authorised');
            error.statusCode = 403;
            throw error;
        }

        if (post.imageUrl !== imageUrl) {
            clearImage(post.imageUrl);
        }

        post.title = title;
        post.content = content;
        post.imageUrl = imageUrl;

        const result = await post.save();
        io.getIO().emit('posts', { action: 'update', post: result });
        res.status(200).json({ message: 'Post is updated', post: result });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};

exports.deletePost = async (req, res, next) => {
    postId = req.params.postId;

    try {
        const post = await Post.findById(postId);
        if (!post) {
            const error = new Error('No post founded');
            error.statusCode = 404;
            throw error;
        }

        if (post.creator.toString() !== req.userId) {
            const error = new Error('Not authorised');
            error.statusCode = 403;
            throw error;
        }

        clearImage(post.imageUrl);

        await Post.findByIdAndRemove(postId);
        const user = await User.findById(req.userId);
        user.posts.pull(postId)
        await user.save();
        io.getIO().emit('posts', { action: 'delete', post: postId });
        res.status(200).json({ message: 'Post is deleted.' });
    } catch (err) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};

const clearImage = filePath => {
    fpath = path.join(__dirname, '..', filePath);
    fs.unlink(fpath, err => console.log(err));
};
