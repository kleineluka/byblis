import * as fs from 'fs';
import * as path from 'path';

/**
 * Parses the header to get the original file extension.
 * @param data The file's encrypted data.
 * @returns The original extension or k9a if not found.
 */
export function parseHeader(data: Buffer): string {
    if (data.length === 0) {
        console.warn("Data is empty, returning default 'k9a'.");
        return "k9a";
    }
    const headerLength = data[0];
    if (headerLength + 1 > data.length) {
        console.warn("Header length byte is invalid, returning default 'k9a'.");
        return "k9a";
    }
    const extensionBytes = data.slice(1, 1 + headerLength);
    try {
        return extensionBytes.toString('utf-8');
    } catch (error) {
        console.error("Failed to decode extension from header:", error);
        return "";
    }
}

/**
 * Creates the header buffer based on the file extension.
 * @param extension The file extension string (NO DOT!!!!)
 * @returns A Buffer containing the header.
 */
export function createHeader(extension: string): Buffer {
    const extensionBytes = Buffer.from(extension, 'utf-8');
    if (extensionBytes.length > 255) {
        throw new Error("Extension is too long! Max 255 bytes, dummy!");
    }
    const header = Buffer.allocUnsafe(1 + extensionBytes.length);
    header[0] = extensionBytes.length;
    extensionBytes.copy(header, 1);
    return header;
}

/**
 * Generates a mask value based on the file name (without extension).
 * @param filePath The full path to the file.
 * @returns The calculated mask value (as a 32-bit integer).
 */
export function makeMask(filePath: string): number {
    let maskValue = 0;
    const baseName = path.parse(filePath).name.toUpperCase();
    for (let i = 0; i < baseName.length; i++) {
        const charCode = baseName.charCodeAt(i);
        maskValue = ((maskValue << 1) ^ charCode) | 0;
    }
    return maskValue;
}

/**
 * Decrypts the k9a file data.
 * @param data The k9a file data buffer.
 * @param filePath The original file path (for the mask).
 * @returns A Buffer with the decrypted data.
 */
export function decrypt(data: Buffer, filePath: string): Buffer {
    if (data.length < 2) {
        console.error("Data too short to decrypt.");
        return Buffer.alloc(0);
    }
    const headerLength = data[0];
    if (headerLength + 2 > data.length) {
        console.error("Header length or data structure invalid.");
        return Buffer.alloc(0);
    }
    let storedDataLength = data[1 + headerLength];
    const encryptedData = data.slice(2 + headerLength);
    let currentMask = makeMask(filePath);
    const dataLength = storedDataLength === 0 ? encryptedData.length : storedDataLength;
    if (dataLength > encryptedData.length) {
        console.error(`Stored data length (${dataLength}) is greater than actual data size (${encryptedData.length})...`);
    }
    const finalDecryptedData = Buffer.alloc(dataLength);
    for (let i = 0; i < dataLength; i++) {
        if (i >= encryptedData.length) {
            console.warn(`Index ${i} out of bounds for encrypted data (length ${encryptedData.length}). Stopping decryption early.`);
            break;
        }
        const encryptedByte = encryptedData[i];
        const decryptedByte = ((encryptedByte ^ currentMask) & 0xFF);
        finalDecryptedData[i] = decryptedByte;
        currentMask = ((currentMask << 1) ^ encryptedByte) | 0;
    }
    return finalDecryptedData;
}

/**
 * Reads a k9a file, decrypts it, and figures out the original filename.
 * @param filePath Path to the .k9a file.
 * @returns An object { data: Buffer, filename: string }
 */
export function decryptFile(filePath: string): { data: Buffer; filename: string } {
    const data = fs.readFileSync(filePath);
    const decryptedData = decrypt(data, filePath);
    const originalExtension = parseHeader(data);
    const baseName = path.parse(filePath).name;
    const originalFilename = originalExtension ? `${baseName}.${originalExtension}` : baseName;
    return { data: decryptedData, filename: originalFilename };
}

/**
 * Encrypts data to the k9a format. Basically the reverse of decrypt.
 * @param data The original file data Buffer.
 * @param filePath The original file path (used for mask and extension).
 * @param advancedPositions Use special encryption ranges based on extension.
 * @returns A Buffer with the encrypted data (including header).
 */
export function encrypt(data: Buffer, filePath: string, advancedPositions: boolean): Buffer {
    const extension = path.extname(filePath).slice(1);
    const header = createHeader(extension);
    const dataLengthByte = data.length > 255 ? 0 : data.length;
    let currentMask = makeMask(filePath);
    let encryptStart = 0;
    let encryptEnd = data.length;
    if (advancedPositions) {
        switch (extension.toLowerCase()) {
            case "json":
                encryptEnd = data.length;
                break;
            case "png":
                encryptEnd = Math.min(100, data.length);
                break;
            case "ogg":
                encryptEnd = Math.min(200, data.length);
                break;
        }
    }
    const encryptedPayload = Buffer.alloc(data.length);
    let dataIndex = 0;
    for (let i = 0; i < data.length; i++) {
        const originalByte = data[i];
        if (i >= encryptStart && i < encryptEnd) {
            const encryptedByte = ((originalByte ^ currentMask) & 0xFF);
            encryptedPayload[dataIndex++] = encryptedByte;
            currentMask = ((currentMask << 1) ^ encryptedByte) | 0;
        } else {
            encryptedPayload[dataIndex++] = originalByte;
        }
    }
    const finalEncryptedData = Buffer.concat([
        header,
        Buffer.from([dataLengthByte]),
        encryptedPayload
    ]);
    return finalEncryptedData;
}

/**
 * Reads a file, encrypts it, and determines the new .k9a filename.
 * @param filePath Path to the original file.
 * @param advancedPositions Use special encryption ranges?
 * @returns An object { data: Buffer, filename: string }
 */
export function encryptFile(filePath: string, advancedPositions: boolean): { data: Buffer; filename: string } {
    const data = fs.readFileSync(filePath);
    const encryptedData = encrypt(data, filePath, advancedPositions);
    const baseName = path.parse(filePath).name;
    const newFilename = `${baseName}.k9a`;
    return { data: encryptedData, filename: newFilename };
}
