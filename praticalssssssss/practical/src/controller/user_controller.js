import { StatusCodes } from "http-status-pro-js";
import bcrypt from bcrypt;
import user from "../model/user";
import jwt from "jsonwebtoken";

export async function register(req,res){
    let {name,email,password,role} =req.body;

    try{

        let exist= await user.findOne({email});

        if(exist){
            return res.status(StatusCodes.CONFLICT.code).json({
                code:StatusCodes.CONFLICT.code,
                message:"User already exists",
                data:null
            });

        }

        let pass = bcrypt.hashSync(password,10);
        password =pass;

        let obj= new user({name,email,password,role});
        await obj.save();

        return res.status(StatusCodes.CREATED.code).json({
            code:StatusCodes.CREATED.code,
            message:"NAYA USER BN GYA",
            data:null
        })


    }
    catch(err){
        console.log(err,"user creation");
        return res.status(StatusCodes.INTERNAL_SERVER_ERROR.code).json({
            code:StatusCodes.INTERNAL_SERVER_ERROR.code,
            message:StatusCodes.INTERNAL_SERVER_ERROR.message,
            data:null

        })
    }




}




