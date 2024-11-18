const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    text: { type: String, required: true },
    imgSrc: { type: String, default: "" },
    time: { type: Date, default: Date.now },
  });

const Post = mongoose.model('Post', postSchema);
module.exports = Post;
