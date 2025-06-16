import {validationResult} from 'express-validator'
import { ApiError } from "../libs/api-error.js";
import { ApiResponse } from '../libs/api-response.js';
export const validate = (req, res, next) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  const extractedError = [];
  errors.array().map((err) =>
    extractedError.push({
      [err.path]: err.msg,
    }),
  );
  res.status(422).json(new ApiResponse(422, extractedError,'Recieved data is not valid'));
  throw new ApiError(422, "Recieved data is not valid", extractedError);
  
};