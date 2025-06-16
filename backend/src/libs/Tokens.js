import jwt from 'jsonwebtoken'
import crypto from 'crypto'
import { ApiError } from './api-error.js';
const genTempToken = function(){

    const unHashedToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(unHashedToken).digest('hex');
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    return {unHashedToken,hashedToken,tokenExpiry};
 
}

const genRefreshToken = function(user){
    return jwt.sign(
      {id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      image: user.image,}
      ,process.env.JWT_REFRESH_TOKEN_SECRET,
      {expiresIn: '7d'}
    )

}
const genAccessToken = function (user) {

    return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      image: user.image,
    },
    process.env.JWT_ACCESS_TOKEN_SECRET,
    {expiresIn: '15m'}
  )

  
}
export  {genTempToken,genRefreshToken,genAccessToken};