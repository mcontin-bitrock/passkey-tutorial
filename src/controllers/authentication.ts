import { Request, Response, NextFunction } from 'express';
import { generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { uint8ArrayToBase64, base64ToUint8Array, base64ToBase64URL } from '../utils/utils';
import { rpID, origin } from '../utils/constants';
import {credentialService} from '../services/credentialService';
import {userService} from '../services/userService'
import {AuthenticatorDevice} from "@simplewebauthn/typescript-types";
import {decodeClientDataJSON, isoBase64URL} from "@simplewebauthn/server/helpers";
import {VerifiedAuthenticationResponse, VerifyAuthenticationResponseOpts} from "@simplewebauthn/server/esm";
import { CustomError } from '../middleware/customError';

export const handleLoginStart = async (req: Request, res: Response, next: NextFunction) => {
    const {username} = req.body;
    try {
        const user = await userService.getUserByUsername(username);
        if (!user) {
            return next(new CustomError('User not found', 404));
        }

        req.session.loggedInUserId = user.id;

        // allowCredentials is purposely for this demo left empty. This causes all existing local credentials
        // to be displayed for the service instead only the ones the username has registered.
        const options = await generateAuthenticationOptions({
            timeout: 60000,
            allowCredentials: [],
            userVerification: 'required',
            rpID,
        });

        req.session.currentChallenge = options.challenge;
        res.send(options);
    } catch (error) {
        next(error instanceof CustomError ? error : new CustomError('Internal Server Error', 500));
    }
};

export const handleLoginFinish = async (req: Request, res: Response, next: NextFunction) => {
    const {body} = req;
    const {currentChallenge, loggedInUserId} = req.session;

    if (!loggedInUserId) {
        return next(new CustomError('User ID is missing', 400));
    }

    if (!currentChallenge) {
        return next(new CustomError('Current challenge is missing', 400));
    }

    console.info("starting handleLoginFinish")

    try {
        const credentialID = isoBase64URL.toBase64(body.rawId);
        const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId);
        const dbCredential : AuthenticatorDevice | null = await credentialService.getCredentialByCredentialId(credentialID, loggedInUserId);
        if (!dbCredential) {
            return next(new CustomError('Credential not registered with this site', 404));
        }

        // @ts-ignore
        const user = await userService.getUserById(dbCredential.userID);
        if (!user) {
            return next(new CustomError('User not found', 404));
        }

        // @ts-ignore
        dbCredential.credentialID = base64ToUint8Array(dbCredential.credentialID)
        // @ts-ignore
        dbCredential.credentialPublicKey = base64ToUint8Array(dbCredential.credentialPublicKey)

        // decodes challenge once
        let clientDataJSON = decodeClientDataJSON(body.response.clientDataJSON);
        let decodedChallenge = Buffer.from(clientDataJSON.challenge, 'base64').toString('utf-8')
        clientDataJSON.challenge = decodedChallenge
        body.response.clientDataJSON = btoa(JSON.stringify(clientDataJSON))

        console.log("did decode challenge once")

        // convert authenticatorData and signature from base64 to base64URL
        let authenticatorData = body.response.authenticatorData
        if (!isoBase64URL.isBase64url(authenticatorData)) {
            body.response.authenticatorData = base64ToBase64URL(authenticatorData)
        }

        console.log("did convert authenticatorData")
        console.log(body.response.authenticatorData)
        
        let signature = body.response.signature
        if (!isoBase64URL.isBase64url(signature)) {
            body.response.signature = base64ToBase64URL(signature)
        }

        console.log("did convert signature:")
        console.log(body.response.signature)
        
        // verification
        const opts: VerifyAuthenticationResponseOpts = {
            response: body,
            expectedChallenge: currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: dbCredential,
        };

        let verification = await verifyAuthenticationResponse(opts);

        console.log("did verify authentication")

        const { verified, authenticationInfo } = verification;

        if (verified) {
            await credentialService.updateCredentialCounter(
                uint8ArrayToBase64(bodyCredIDBuffer),
                authenticationInfo.newCounter
            );
            res.send({verified: true});
        } else {
            next(new CustomError('Verification failed', 400));
        }
    } catch (error) {
        next(error);
    } finally {
        req.session.currentChallenge = undefined;
        req.session.loggedInUserId = undefined;
    }
};