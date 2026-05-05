
import { required } from "joi";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:true,
        maxlength:50
    },
    email:{
        type:String,
        required:true,
        unique:true,


    },
    password:{
        type:String,
        match:[
            /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(=.*[@$!%*?&]).{6,}$/
        ],
        required:true
    },
    role:{
        type:String,
        required:true
    }
})

export default mongoose.model("user",userSchema);