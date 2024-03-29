const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  image: { type: String },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
module.exports = {
  User,
  Post,
};