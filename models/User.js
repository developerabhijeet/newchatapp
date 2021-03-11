const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const {isEmail} = require('validator')
const userSchema = new mongoose.Schema({
  name:{
    type: String,
    required: [true, 'Please Enter a name']
  },
  email:{
    type: String,
    required: [true, 'Please Enter a email'],
    unique: true,
    lowercase:true,
    validate : [isEmail, 'Please Enter a valid Email']
  },
  password:{
    type: String,
    required: [true, 'Please Enter a password'],
    minlength: [6,'The password should be six character long']
  },
  profession:{
    type: String,
    required: [true, 'Please Enter a profession']
  },
})
userSchema.pre('save',async function(next){
  const salt = await bcrypt.genSalt();
  this.password = await bcrypt.hash(this.password, salt);
  
  next()
})
userSchema.statics.login = async function(email,password){
  const user = await this.findOne({email});
  if(user){
    const isAuthenticated  = await bcrypt.compare(password, user.password);
    if(isAuthenticated){
      return user;

    }
    throw Error('incorrect pwd');
  }else{
    throw Error('incorrect email');
  }
}
const User = mongoose.model('user',userSchema);
module.exports = User;