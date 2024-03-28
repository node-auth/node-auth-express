const jwt = require('jsonwebtoken');
const axios = require('axios');
import { Request, Response, NextFunction } from 'express';

/**
 * Interfaces
 */
interface OauthConfig {
    issuerUrl: string,
    baseUrl?: string,
    clientId?: string,
    clientSecret?: string,
    audience: string,
    resourceOwner: boolean,
    secretKey?: string
}

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
 * Initialization
 * @param oauthConfigParam 
 * @returns 
 */
function nodeAuth(oauthConfigParam: OauthConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
        /**
         * Set the nodeAuthConfig for next middleware consumption
         */
        req.nodeAuthConfig = oauthConfigParam;
        next();
    }
}


/**
 * Validate token
 * @param token 
 * @returns object
 */
async function validateToken(token: string, nodeAuthConfig: OauthConfig) {
    try {
        console.log(token);
        if(nodeAuthConfig.resourceOwner) {
            return new Promise((resolve, reject) => {
                jwt.verify(token, nodeAuthConfig.secretKey, (err: any, decoded: any) => {
                    if (err) {
                        reject({success: false, message: err})
                    }
                    /** Validate audience */
                    if(decoded.aud != nodeAuthConfig.audience) reject({success: false, message: err});
                    /** Validate issuer */
                    if(decoded.iss != nodeAuthConfig.issuerUrl) reject({success: false, message: err});
                    resolve({success: true, message: 'authenticated', data: decoded})
                });
            })
        } else {
            const csrfTokenResponse = await axios.get(`${nodeAuthConfig.issuerUrl}/o/csrf-token`);
            const response = await axios.post(`${nodeAuthConfig.issuerUrl}/o/instrospect`, {
                client_id: nodeAuthConfig.clientId,
                client_secret: nodeAuthConfig.clientSecret,
                token
            }, {
                headers: {
                    'x-csrf-token': csrfTokenResponse.data['csrfToken']
                }
            });
            return response.data;
        }
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
        if(validatedToken['success'] == false) return res.status(401).json({ success: false, message: 'Unauthorize'});
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
        const userPermissions = req.user.permissions?.[req.nodeAuthConfig.audience];
        if (!userPermissions) {
            return res.status(401).json({ success: false, message: 'Unauthorize'});
        }
        for (let i = 0; i < permissionList.length; i++) {
            const checkPermission = userPermissions.includes(permissionList[i]);
            if (!checkPermission) {
                isPermitted = false;
                break;
            }
        }
        if(!isPermitted) return res.status(401).json({ success: false, message: 'Unauthorize'});
        next();
    }
}

module.exports = { nodeAuth, authenticate, permissions }