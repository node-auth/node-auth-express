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
function nodeAuth(oauthConfigParam: OauthConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
        /**
         * Set configuration
         */
        setOauthConfig(oauthConfigParam);

        /**
         * Set the nodeAuthConfig for next middleware consumption
         */
        req.nodeAuthConfig = oauthConfig;

        next();
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
async function validateToken(token: string, nodeAuthConfig: OauthConfig) {
    try {
        const csrfTokenResponse = await axios.get(`${nodeAuthConfig.issuerBaseUrl}/o/csrf-token`);
        const response = await axios.post(`${nodeAuthConfig.issuerBaseUrl}/o/instrospect`, {
            client_id: nodeAuthConfig.clientId,
            client_secret: nodeAuthConfig.clientSecret,
            token
        }, {
            headers: {
                'x-csrf-token': csrfTokenResponse.data['csrfToken']
            }
        });
        return response.data;
    } catch(err) {
        return {success: false, message: err}
    }
}

/**
 * Authenticate
 * @param req 
 * @param res 
 * @param next 
 */
function authenticate(req: Request, res: Response, next: NextFunction) {
    const _auth = async () => {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
        if (!token) {
            return res.status(401).json({ success: false, message: 'Unauthorize' });
        }
        const _nodeAuthConfig = req.nodeAuthConfig;
        const validatedToken = await validateToken(token, _nodeAuthConfig);
        if(validatedToken['success'] == false) return res.status(401).json({ success: false, message: 'Unauthorize'})
        req.user = validatedToken.data;
        next();
    }
    _auth();
}

/**
 * Permission
 * @param req 
 * @param res 
 * @param next 
 */
function permissions(permissionList: string[]) {
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

module.exports = { nodeAuth, authenticate, permissions }