"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const jwt = require('jsonwebtoken');
const axios = require('axios');
/**
 * Initialization
 * @param oauthConfigParam
 * @returns
 */
function nodeAuth(oauthConfigParam) {
    return (req, res, next) => {
        /**
         * Set the nodeAuthConfig for next middleware consumption
         */
        req.nodeAuthConfig = oauthConfigParam;
        next();
    };
}
/**
 * Validate token
 * @param token
 * @returns object
 */
function validateToken(token, nodeAuthConfig, req) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            if (nodeAuthConfig.resourceOwner) {
                return new Promise((resolve, reject) => {
                    jwt.verify(token, nodeAuthConfig.secretKey, (err, decoded) => {
                        if (err) {
                            reject({ success: false, message: err });
                        }
                        /** Validate audience */
                        if (!decoded.permissions[nodeAuthConfig.audience]) {
                            reject({ success: false, message: err });
                        }
                        /** Validate issuer */
                        if (decoded.iss != nodeAuthConfig.issuerUrl) {
                            reject({ success: false, message: err });
                        }
                        resolve({ success: true, message: 'authenticated', data: decoded });
                    });
                }).catch(err => {
                    console.error('Promise rejected:', err);
                    throw err;
                });
            }
            else {
                const csrfTokenResponse = yield axios.get(`${nodeAuthConfig.issuerUrl}/o/csrf-token`);
                const response = yield axios.post(`${nodeAuthConfig.issuerUrl}/o/instrospect`, {
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
        }
        catch (err) {
            return { success: false, message: err };
        }
    });
}
/**
 * Authenticate
 * @param req
 * @param res
 * @param next
 */
function authenticate(req, res, next) {
    try {
        const _auth = () => __awaiter(this, void 0, void 0, function* () {
            const authHeader = req.headers['authorization'];
            const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
            if (!token) {
                return res.status(401).json({ success: false, message: 'Unauthorize' });
            }
            const _nodeAuthConfig = req.nodeAuthConfig;
            const validatedToken = yield validateToken(token, _nodeAuthConfig, req);
            if (validatedToken['success'] == false)
                return res.status(401).json({ success: false, message: 'Unauthorize' });
            req.user = validatedToken.data;
            next();
        });
        _auth();
    }
    catch (err) {
        return res.status(401).json({ success: false, message: 'Unauthorize' });
    }
}
/**
 * Permission
 * @param req
 * @param res
 * @param next
 */
function permissions(permissionList) {
    return (req, res, next) => {
        var _a;
        try {
            let isPermitted = true;
            const userPermissions = (_a = req.user.permissions) === null || _a === void 0 ? void 0 : _a[req.nodeAuthConfig.audience];
            if (!userPermissions) {
                return res.status(401).json({ success: false, message: 'Unauthorize' });
            }
            for (let i = 0; i < permissionList.length; i++) {
                const checkPermission = userPermissions.includes(permissionList[i]);
                if (!checkPermission) {
                    isPermitted = false;
                    break;
                }
            }
            if (!isPermitted)
                return res.status(401).json({ success: false, message: 'Unauthorize' });
            next();
        }
        catch (err) {
            return res.status(401).json({ success: false, message: 'Unauthorize' });
        }
    };
}
module.exports = { nodeAuth, authenticate, permissions };
