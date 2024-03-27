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
 * Configuration
 * @param req
 * @param res
 * @param next
 */
let oauthConfig = {
    issuerBaseUrl: '',
    baseUrl: '',
    clientId: '',
    clientSecret: '',
    audience: ''
};
/**
 * Initialization
 * @param oauthConfigParam
 * @returns
 */
function nodeAuth(oauthConfigParam) {
    return (req, res, next) => {
        /**
         * Set configuration
         */
        setOauthConfig(oauthConfigParam);
        /**
         * Set the nodeAuthConfig for next middleware consumption
         */
        req.nodeAuthConfig = oauthConfig;
        next();
    };
}
/**
 * Set authentication configuration
 * @param oauthConfigParam
 */
function setOauthConfig(oauthConfigParam) {
    var _a, _b, _c, _d, _e;
    oauthConfig.issuerBaseUrl = (_a = oauthConfigParam.issuerBaseUrl) !== null && _a !== void 0 ? _a : '';
    oauthConfig.baseUrl = (_b = oauthConfigParam.baseUrl) !== null && _b !== void 0 ? _b : '';
    oauthConfig.clientId = (_c = oauthConfigParam.clientId) !== null && _c !== void 0 ? _c : '';
    oauthConfig.clientSecret = (_d = oauthConfigParam.clientSecret) !== null && _d !== void 0 ? _d : '';
    oauthConfig.audience = (_e = oauthConfigParam.audience) !== null && _e !== void 0 ? _e : '';
}
/**
 * Validate token
 * @param token
 * @returns object
 */
function validateToken(token, nodeAuthConfig) {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const csrfTokenResponse = yield axios.get(`${nodeAuthConfig.issuerBaseUrl}/o/csrf-token`);
            const response = yield axios.post(`${nodeAuthConfig.issuerBaseUrl}/o/instrospect`, {
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
    const _auth = () => __awaiter(this, void 0, void 0, function* () {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>
        if (!token) {
            return res.status(401).json({ success: false, message: 'Unauthorize' });
        }
        const _nodeAuthConfig = req.nodeAuthConfig;
        const validatedToken = yield validateToken(token, _nodeAuthConfig);
        if (validatedToken['success'] == false)
            return res.status(401).json({ success: false, message: 'Unauthorize' });
        req.user = validatedToken.data;
        next();
    });
    _auth();
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
        let isPermitted = true;
        const userPermissions = (_a = req.user.permissions) === null || _a === void 0 ? void 0 : _a[oauthConfig.audience];
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
    };
}
module.exports = { nodeAuth, authenticate, permissions };
