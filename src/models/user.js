const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Task = require('./task');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate(value){
            if(!validator.isEmail(value)){
                throw new Error('Invalid Email')
            }
        }
    },
    password:{
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if(value.toLowerCase().includes('password')){
                throw new Error('Passord cannot contain "Password')
            }
        }
    },
    age: {
        type: Number,
        validate(value) {
            if (value < 0){
                throw new Error('Age must be a positive number');
            }
        }
    },
    avatar:{
        type: Buffer
    },
    tokens: [{
        token: {
            type: String,
            required: true,
        }
    }]
},{
    timestamps: true
});

//Create virtual tasks document in users collections. 
userSchema.virtual('tasks', {
    ref: 'Task',
    localField: '_id',
    foreignField: 'owner'
})


// Modify user data before return
userSchema.methods.toJSON = function () {
    const userObject = this.toObject();
    delete userObject.password;
    delete userObject.tokens;
    delete userObject.avatar;

    return userObject;
}

//Generate auth token
userSchema.methods.generateAuthToken = async function(){
    const token = jwt.sign({ _id: this._id.toString() }, process.env.JWT_SECRET);

    this.tokens = this.tokens.concat({ token });
    await this.save();

    return token;
}

//find credentials on User model
userSchema.statics.findByCredentials = async (email, password) =>{
    const user = await User.findOne({email});
    const isMatch = await bcrypt.compare(password, user.password);
    
    if(!user || !isMatch){
        throw new Error(' Unable to login');
    }
    return user;
}

// Hash the plain text password before saving and update.
userSchema.pre('save', async function (next) {
    const user = this;
    if(user.isModified('password')){
        user.password = await bcrypt.hash(user.password, 8);
    }
    next();
})

// Delete user's task when user is removed
userSchema.pre('remove', async function (next){
    await Task.deleteMany({owner : this._id});
    next();
})


const User = mongoose.model('User', userSchema)

module.exports = User