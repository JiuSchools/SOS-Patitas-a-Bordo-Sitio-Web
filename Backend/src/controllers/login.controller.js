import User from "../models/user";

const LoginController = async (req,res) =>{
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
    }

};

export default LoginController;