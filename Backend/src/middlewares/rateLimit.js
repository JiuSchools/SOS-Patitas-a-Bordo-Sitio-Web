import ratelimit, { rateLimit } from 'express-rate-limit';

export const loginLimiter = rateLimit({
    windowMs: 15*60*1000,  // 15 minutes
    max: 5, 
    message: 'Demasiados intentos para esta dirección de IP, por favor intentalo más tarde.' 
});

