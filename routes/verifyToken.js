const jwt = require('jsonwebtoken');

const verifyToken = (req,res,next)=>{
    const authHeader = req.headers.token;

    if(authHeader){

        const token = authHeader.split(" ")[1]; // for spliting token header 1st element in array

        jwt.verify(token, process.env.JWT_SEC, (err,user)=>{
            if(err) res.status(403).json("Token is not valid!");
            req.user = user;
            next();
        })
    }
    else{
        return res.status(401).json("You are not authenticated");
    }
}

const verifyTokenAndAuthorization = (req, res, next)=>{
    verifyToken(req, res, ()=>{
        if(req.user.id === req.params.id || req.user.is_Admin){
            next();
        }
        else{
             res.status(403).json("You are not allowed");
        }
    })
}

const verifyTokenAndAdmin = (req, res, next)=>{
    verifyToken(req, res, ()=>{
        if(req.user.is_Admin){
            next();
        }
        else{
             res.status(403).json("You are not allowed");
        }
    })
}

module.exports = {
    verifyToken,
    verifyTokenAndAuthorization,
    verifyTokenAndAdmin
};