import { isoBase64URL } from "@simplewebauthn/server/helpers";

export const uint8ArrayToBase64 = (uint8Array: Uint8Array): string =>
    Buffer.from(uint8Array).toString('base64');

export const base64ToUint8Array = (base64: string): Uint8Array =>
    new Uint8Array(Buffer.from(base64, 'base64'));

export function base64ToBase64URL(base64: string): string {
    const atteObjBytes = isoBase64URL.toBuffer(base64, 'base64');
    base64 = isoBase64URL.fromBuffer(atteObjBytes);
    return base64
}