import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from "bcrypt";

export const hashPassword = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPass = (user, password) => bcrypt.compareSync(password, user.password);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default __dirname;