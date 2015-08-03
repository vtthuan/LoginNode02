var mongoose = require('mongoose');
var bCrypt = require('bcrypt-nodejs');

var userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    set: function(value) {return value.trim().toLowerCase()},
    validate: [
      function(email) {
        return (email.match(/[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/i) != null)},
      'Invalid email'
    ]
  },
  password: String,
  admin: {
    type: Boolean,
    default: false
  }
});

// Generates hash using bCrypt
userSchema.methods.generateHash = function (password) {
    return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}

// checking if password is valid
userSchema.methods.validPassword = function (password) {
    return bCrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);