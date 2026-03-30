// node imports, ts imports, etc.
let fs;
let path;
try {
    fs = require('fs');
    path = require('path');
} catch (e) {
    console.log("Failed to load Node.js modules. This is likely running in a browser context.", 'error', 'Menu Payload', e);
}
import { fileTypeFromBuffer } from 'file-type';

const ASSET_SIG = Buffer.from("TCOAAL");
const SIG_LEN = ASSET_SIG.length;

/**
 * Tries to guess the file extension from the data's magic bytes (MIME type).
 * @param data The file data Buffer (decrypted, preferably!).
 * @returns A likely file extension string (like 'png', 'jpg', 'ogg') or 'dat' as a fallback.
 */
async function getExtensionFromMime(data: Buffer): Promise<string> {
    if (!data || data.length === 0) {
        console.warn("Cannot determine MIME type from empty data. Falling back to 'dat'.");
        return "dat";
    }
    try {
        const type = await fileTypeFromBuffer(data);
        const mime = type?.mime;
        console.log(`Detected MIME: ${mime ?? 'unknown'}`);
        switch (mime) {
            case "image/png": return "png";
            case "image/gif": return "gif";
            case "image/jpeg": return "jpg";
            case "image/bmp": return "bmp";
            case "image/webp": return "webp";
            case "image/tiff": return "tiff";
            case "audio/ogg": return "ogg";
            case "audio/mpeg": return "mp3";
            case "audio/wav":
            case "audio/wave":
                return "wav";
            case "text/plain": return "txt";
            case "application/json": return "json";
            default:
                console.log(`Unknown or unsupported MIME type: ${mime}. Falling back to 'dat'.`);
                return "dat";
        }
    } catch (error) {
        console.error("Error detecting file type:", error);
        return "dat";
    }
}

/**
 * Generates a mask value based on the file name (without extension), uppercase.
 * Warning: Slightly different logic than k9a's mask.
 * @param filePath The full path to the file.
 * @returns The calculated mask value (as a 32-bit integer).
 */
function makeMask(filePath: string): number {
    const baseName = path.parse(filePath).name.toUpperCase();
    if (!baseName) {
        return 0;
    }
    let maskValue = 0;
    for (let i = 0; i < baseName.length; i++) {
        const charCode = baseName.charCodeAt(i);
        maskValue = ((maskValue << 1) ^ charCode) | 0; // | 0 for 32-bit integer conversion
    }
    return maskValue;
}

/**
 * Decrypts data in Version 3.0 of the game.
 * @param data The encrypted data Buffer.
 * @param filePath The original file path (used for mask generation).
 * @returns A Buffer with the decrypted data, or the original data if signature doesn't match.
 */
export function decrypt(data: Buffer, filePath: string): Buffer {
    if (data.length < SIG_LEN + 1 || !data.subarray(0, SIG_LEN).equals(ASSET_SIG)) {
        console.warn("Data doesn't have the expected signature or is too short. Returning original data.");
        return Buffer.from(data);
    }
    const bytesToDecryptIndicator = data[SIG_LEN];
    const payload = data.slice(SIG_LEN + 1);
    const payloadLen = payload.length;
    if (payloadLen === 0) {
        return Buffer.alloc(0);
    }
    const numBytesToDecrypt = bytesToDecryptIndicator === 0
        ? payloadLen
        : Math.min(bytesToDecryptIndicator, payloadLen); // remanent of .k9a logic.. oops :(
    const maskVal = makeMask(filePath);
    let xorKey: number = (maskVal + 1) & 0xFF;
    const decryptedPayload = Buffer.alloc(payloadLen);
    for (let i = 0; i < payloadLen; i++) {
        const currentByte = payload[i];
        if (i < numBytesToDecrypt) {
            const decryptedByte = currentByte ^ xorKey;
            decryptedPayload[i] = decryptedByte;
            xorKey = ((xorKey << 1) ^ currentByte) & 0xFF;
        } else {
            decryptedPayload[i] = currentByte;
        }
    }
    return decryptedPayload;
}

/**
 * Encrypts data using the 'TCOAAL' signature and XOR obfuscation.
 * @param data The original file data Buffer.
 * @param filePath The original file path (used for mask generation).
 * @param advancedPositions Affects the indicator byte if data length <= 255. 
 * @returns A Buffer with the encrypted data (signature + indicator + payload).
 */
export function encrypt(data: Buffer, filePath: string): Buffer {
    const dataLen = data.length;
    let indicator = 0;
    const maskVal = makeMask(filePath);
    let xorKey: number = (maskVal + 1) & 0xFF;
    const encryptedData = Buffer.allocUnsafe(SIG_LEN + 1 + dataLen); // unsafe is fine since it's filled immediately
    ASSET_SIG.copy(encryptedData, 0);
    encryptedData[SIG_LEN] = indicator;
    const payloadOffset = SIG_LEN + 1;
    for (let i = 0; i < dataLen; i++) {
        const originalByte = data[i];
        const encryptedByte = originalByte ^ xorKey;
        encryptedData[payloadOffset + i] = encryptedByte;
        xorKey = ((xorKey << 1) ^ encryptedByte) & 0xFF;
    }
    return encryptedData;
}

/**
 * Reads an encrypted file, decrypts it, and determines the original filename with extension.
 * @param filePath Path to the encrypted file (expected to have TCOAAL sig).
 * @returns A Promise resolving to an object { data: Buffer, filename: string } or rejects on error.
 */
export async function decryptFile(filePath: string): Promise<{ data: Buffer; filename: string }> {
    console.log(`Attempting to decrypt file: ${filePath}`);
    let data: Buffer;
    try {
        data = fs.readFileSync(filePath);
    } catch (error: any) {
        console.error(`Failed to read file for decryption '${filePath}': ${error.message}`);
        throw new Error(`Failed to read file: ${filePath}`);
    }
    const decryptedData = decrypt(data, filePath);
    const fileExtension = await getExtensionFromMime(decryptedData);
    const fileStem = path.parse(filePath).name;
    if (!fileStem) {
        console.warn(`Could not extract a valid file stem from '${filePath}'. Using fallback name.`);
        return { data: decryptedData, filename: `decrypted_noname.${fileExtension}` };
    }
    const outputFilename = `${fileStem}.${fileExtension}`;
    console.log(`Decrypted data; suggested filename: ${outputFilename}`);
    return { data: decryptedData, filename: outputFilename };
}

/**
 * Reads a file, encrypts it, and determines the output filename (which is just the original stem).
 * @param filePath Path to the original file to encrypt.
 * @returns An object { data: Buffer, filename: string } or throws on error.
 */
export function encryptFile(filePath: string): { data: Buffer; filename: string } {
    console.log(`Attempting to encrypt file: ${filePath}`);
    let data: Buffer;
    try {
        data = fs.readFileSync(filePath);
    } catch (error: any) {
        console.error(`Failed to read file for encryption '${filePath}': ${error.message}`);
        throw new Error(`Failed to read file: ${filePath}`);
    }
    const encryptedData = encrypt(data, filePath);
    const fileStem = path.parse(filePath).name;
    if (!fileStem) {
        console.warn(`Could not extract a valid file stem from '${filePath}'. Using fallback name.`);
        return { data: encryptedData, filename: "encrypted_noname" };
    }
    const outputFilename = fileStem;
    console.log(`Encrypted data; output filename: ${outputFilename}`);
    return { data: encryptedData, filename: outputFilename };
}
