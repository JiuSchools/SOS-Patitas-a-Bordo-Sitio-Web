import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import validator, { trim } from 'validator';
import jwt from 'jsonwebtoken';


const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        validate: [validator.isEmail, 'Por favor ingresa una dirección de correo válida.']
    },
    password: {
        type: String,
        required: true,
        minlenght: [8, 'La contraseña debe de ser minímo de 8 caracteres de largo'],
        maxlenght: [128,'La contraseña debe de ser máximo de 128 caracteres de largo'] 
    },
    loginCount: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

// Hash password before saving to database
userSchema.pre('save', async function(){
    const user = this;
    if(!user.isModified('password')){
        return;
    }
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);

});

// Increment login count when user logs in
userSchema.methods.incrementLoginCount = async function (){
    this.loginCount += 1;
    return await this.save();
};

// Generate a JWT token
userSchema.methods.generateAuthToken = function () {
    const token = jwt.sign({_id: this._id}, process.env.JWT_SECRET, {expiresIn: '1d'});
    return token;
};

userSchema.statics.findByToken = async function (token) {
    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return await this.findOne({ _id: decoded._id });
    } catch(err){
        throw new Error(`Error al verificar el token: ${err.message}`);
    }
};

const User = mongoose.model('User', userSchema);

export default User;





