const mongoose = require('mongoose')
const validator = require('validator')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const { v4: uuidv4 } = require('uuid');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim:true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate(value) {
            if (!validator.isEmail(value)) {
                throw new Error('Email is invalid')
            }
        }
    },
    password: {
        type: String,
        required: true,
        trim: true,
        validate(value) {
            if (value.length < 6) {
                throw new Error('The length must be more than 6 characters')
            }
            if (value.includes('password')) {
                throw new Error("The password must not contain word 'password'")
            }
        }
    },
    tokens: [{
        accessToken: {
            type: String,
            required: true
        },
        refreshTokenHashed: {
            type: String,
            required: true
        }
    }]
}, {
    timestamps: true
})

userSchema.pre('save', async function (next) {
    const user = this
    if (user.isModified('password')) {
        user.password = await bcrypt.hash(user.password, 8)
    }
    next()
})

userSchema.methods.toJSON = function () {
    const user = this
    const userObject = user.toObject()
    
    delete userObject.password
    delete userObject.tokens
    delete userObject.avatar
    return userObject
}

userSchema.methods.generateTokens = async function () {
    try {
        const user = this
        const accessToken = jwt.sign({_id: user._id.toString(), type: 'access' }, process.env.JWT_ACCESS_SECRET, { algorithm: 'HS512' })
        const refreshToken = jwt.sign({_id: uuidv4(), type: 'refresh' }, process.env.JWT_REFRESH_SECRET,  { algorithm: 'HS512' })
        const refreshTokenHashed = await bcrypt.hash(refreshToken, 8)
        user.tokens = user.tokens.concat({ accessToken, refreshTokenHashed })
        await user.save()
        return { accessToken, refreshToken }
    } catch (e) {
        return e
    }   
}

userSchema.statics.findByCredentials = async (email, password) => {
    try {
        const user = await User.findOne({ email })
    if (!user) {
        throw new Error('Unable to login')
    }
    const isMatch = await bcrypt.compare(password, user.password)
    if (!isMatch) {
        throw new Error('Unable to login')
    }
    return user
    } catch (e) {
        return e;
    }
    
}

const User = mongoose.model('User', userSchema )

module.exports = User