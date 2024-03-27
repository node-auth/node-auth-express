const jwt = require('jsonwebtoken');
const axios = require('axios');
import { Request, Response, NextFunction } from 'express';
import { OauthConfig } from './interfaces';

declare global {
    namespace Express {
        interface Request {
            nodeAuthConfig: OauthConfig,
            user: {
                client_id?: string;
                client_secret?: string;
                ip?: string;
                grant_type?: string;
                user_id?: number;
                user_uuid?: string;
                email?: string;
                permissions?: { [url: string]: string[] };
                [key: string]: any;
            }
        }
    }
}

/**
 * Configuration
 * @param req 
 * @param res 
 * @param next 
 */
let oauthConfig : OauthConfig = {
    issuerBaseUrl: '',
    baseUrl: '',
    clientId: '',
    clientSecret: '',
    audience: ''
}

/**
 * Initialization
 * @param oauthConfigParam 
 * @returns 
 */
async function auth(oauthConfigParam: OauthConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
        /**
         * Set configuration
         */
        setOauthConfig(oauthConfigParam);

        /**
         * Set the nodeAuthConfig for next middleware consumption
         */
        req.nodeAuthConfig = oauthConfig;
    }
}

/**
 * Set authentication configuration
 * @param oauthConfigParam 
 */
function setOauthConfig(oauthConfigParam: OauthConfig) {
    oauthConfig.issuerBaseUrl = oauthConfigParam.issuerBaseUrl ?? '';
    oauthConfig.baseUrl = oauthConfigParam.baseUrl ?? '';
    oauthConfig.clientId = oauthConfigParam.clientId ?? '';
    oauthConfig.clientSecret = oauthConfigParam.clientSecret ?? '';
    oauthConfig.audience = oauthConfigParam.audience ?? '';
}

/**
 * Validate token
 * @param token 
 * @returns object
 */
async function validateToken(token: string) {
    try {
        const csrfTokenResponse = await axios.get(`${oauthConfig.issuerBaseUrl}/o/csrf-token`);
        const response = await axios.post(`${oauthConfig.issuerBaseUrl}/o/instrospect`, {
            client_id: oauthConfig.clientId,
            client_secret: oauthConfig.clientSecret,
            token
        }, {
            headers: {
                'X-CSRF-Token': csrfTokenResponse.data['csrfToken']
            }
        });
        return response.data;
    } catch(err) {
        return {success: false, message: 'Invalid token'}
    }
}

/**
 * Authenticate
 * @param req 
 * @param res 
 * @param next 
 */
async function authenticate(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
    if (!token) {
        return res.status(401).json({ success: false, message: 'Unauthorize' });
    }
    const validatedToken = await validateToken(token);
    if(validatedToken['success'] == false) return res.status(401).json({ success: false, message: 'Unauthorize'})
    req.user = validatedToken.data;
    next();
}

/**
 * Permission
 * @param req 
 * @param res 
 * @param next 
 */
async function permissions(permissionList: string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
        let isPermitted = true;
        const userPermissions = req.user.permissions?.[oauthConfig.baseUrl];
        if (!userPermissions) {
            return res.status(401).json({ error: 'Permissions not available' });
        }
        for (let i = 0; i < permissionList.length; i++) {
            const checkPermission = userPermissions.includes(permissionList[i]);
            if (!checkPermission) {
                isPermitted = false;
                break;
            }
        }
        if(!isPermitted) return res.status(401).json({ error: 'Unauthorize' });
        next();
    }
}

module.exports = { auth, authenticate, permissions }