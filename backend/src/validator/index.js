import { body } from "express-validator";

const userRegistrationValidator = () => {
  return [
    body("email")
      .trim()
      .notEmpty().withMessage("Email is required")
      .isEmail().withMessage("Email is invalid"),
    body("password")
      .trim()
      .notEmpty().withMessage("Password is required")
      .isLength({ min: 3 }).withMessage("Password should be at least 3 characters")
      .isLength({ max: 20 }).withMessage("Password cannot exceed 20 characters"),
    body("name")
      .trim()
      .notEmpty().withMessage("Name is required")
      .isLength({ min: 2 }).withMessage("Name should be at least 2 characters")
      .isLength({ max: 25 }).withMessage("Name cannot exceed 13 characters"),
     
  ];
};
const userLoginValidator = () => {
  return [
    body("email").isEmail().withMessage("Email is not valid"),
    body("password").notEmpty().withMessage("Password cannot be empty"),
  ];
};
const PasswordChangeValidator = () => {
    return [
        body('password')
        .trim()
        .notEmpty().withMessage("Password is required")
        .isLength({min:3}).withMessage("Password should be at least 6 characters"),

        body('confirmPassword')
        .trim()
        .notEmpty().withMessage("Password is required")
        .isLength({min:3}).withMessage("Password should be at least 6 characters")
    ]
}
export { userRegistrationValidator, userLoginValidator, PasswordChangeValidator };