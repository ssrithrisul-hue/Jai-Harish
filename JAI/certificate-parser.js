/* =========================================================================
 * certificate-parser.js
 * -------------------------------------------------------------------------
 * Reads an X.509 certificate (PEM or DER) completely in the browser.
 * No libraries are used and nothing is sent to a server.
 *
 * PEM = the raw bytes base64-encoded between
 *       "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----"
 * DER = the raw binary form of the same certificate
 *
 * DER encoding rule we rely on (the only rule we need):
 *   every value is  Tag(1 byte) | Length(1-5 bytes) | Value(bytes)
 *   Tag 0x30 = SEQUENCE, 0x31 = SET, 0x02 = INTEGER, 0x03 = BIT STRING, ...
 *   Length byte < 128  -> that byte IS the length
 *   Length byte 0x80|n -> the next n bytes are the length (big-endian)
 *
 * Certificate ::= SEQUENCE {
 *   tbsCertificate     SEQUENCE {
 *     version          [0] INTEGER              (optional)
 *     serialNumber     INTEGER
 *     signature        AlgorithmIdentifier
 *     issuer           Name,
 *     validity         SEQUENCE { notBefore, notAfter },
 *     subject          Name,
 *     subjectPublicKeyInfo SEQUENCE { algorithm, publicKey BIT STRING }
 *   },
 *   signatureAlgorithm AlgorithmIdentifier
 *   signatureValue     BIT STRING }
 * ========================================================================= */
'use strict';

(function (global) {

/* Small error type so the UI can show our message instead of a stack trace. */
class CertificateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CertificateError';
  }
}

/* ---------- friendly names for the numbers the certificate contains ------- */

/* The pieces of a name (Distinguished Name). */
const ATTRIBUTE_NAMES = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'STREET',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'SERIAL',
  '2.5.4.15': 'BUSINESS CATEGORY',
  '2.5.4.17': 'POSTAL CODE',
  '2.5.4.20': 'TEL',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'EMAIL',
};

const VERSION_NAMES = { 0: 'v1', 1: 'v2', 2: 'v3' };

/* ---------- step 1: read the DER building blocks ------------------------- */

/**
 * Read one DER block (tag + length + value) starting at `offset`.
 * Returns { tag, start, valueStart, valueEnd } where valueEnd points just
 * past the value. `bytes` is a Uint8Array.
 */
function readBlock(bytes, offset) {
  const start = offset;
  const tag = bytes[offset];
  if (tag === undefined) throw new CertificateError('The certificate data ended unexpectedly.');

  // A tag whose low 5 bits are all set uses extra tag bytes (rare here).
  offset += 1;
  if ((tag & 0x1f) === 0x1f) {
    while (bytes[offset] & 0x80) offset += 1;
    offset += 1;
  }

  let length = bytes[offset];
  if (length === undefined) throw new CertificateError('The certificate data ended unexpectedly.');
  offset += 1;

  if (length === 0x80) {
    throw new CertificateError('The file uses an unsupported DER encoding (indefinite length).');
  }
  if (length & 0x80) {
    const count = length & 0x7f; // number of length bytes that follow
    length = 0;
    for (let i = 0; i < count; i += 1) {
      if (bytes[offset] === undefined) throw new CertificateError('The certificate data ended unexpectedly.');
      length = length * 256 + bytes[offset];
      offset += 1;
    }
  }

  const valueEnd = offset + length;
  if (valueEnd > bytes.length) throw new CertificateError('The certificate data is incomplete or damaged.');
  return { tag, start, valueStart: offset, valueEnd };
}

/** Split a SEQUENCE/SET block into the blocks it contains. */
function readChildren(bytes, block) {
  const children = [];
  let offset = block.valueStart;
  while (offset < block.valueEnd) {
    const child = readBlock(bytes, offset);
    children.push(child);
    offset = child.valueEnd;
  }
  return children;
}

/** Turn an OBJECT IDENTIFIER block into a readable "1.2.840..." string. */
function readOid(bytes, block) {
  const first = bytes[block.valueStart];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = block.valueStart + 1; i < block.valueEnd; i += 1) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join('.');
}

/** Turn an INTEGER block into an upper-case hex string ("0A:1B:2C"). */
function readHex(bytes, block) {
  const hex = [];
  for (let i = block.valueStart; i < block.valueEnd; i += 1) {
    hex.push(bytes[i].toString(16).toUpperCase().padStart(2, '0'));
  }
  // Remove the leading 00 that DER uses to keep a positive number positive.
  if (hex.length > 1 && hex[0] === '00') hex.shift();
  return hex.join(':');
}

/** Decode a text value (PrintableString, UTF8String, IA5String, BMPString). */
function readText(bytes, block) {
  const raw = bytes.subarray(block.valueStart, block.valueEnd);
  if (block.tag === 0x1e) { // BMPString: 2 bytes per character, big-endian
    let text = '';
    for (let i = 0; i + 1 < raw.length; i += 2) {
      text += String.fromCharCode((raw[i] << 8) | raw[i + 1]);
    }
    return text;
  }
  if (block.tag === 0x0c) return new TextDecoder('utf-8').decode(raw); // UTF8String
  return new TextDecoder('iso-8859-1').decode(raw);                   // the rest
}

/**
 * Decode UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ).
 * UTCTime uses two-digit years: 50-99 means 1950-1999, 00-49 means 2000-2049.
 */
function readTime(bytes, block) {
  const text = readText(bytes, block).trim();
  const match = /^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(text);
  if (!match) throw new CertificateError('Could not read a validity date from the certificate.');

  let year = Number(match[1]);
  if (match[1].length === 2) year += year < 50 ? 2000 : 1900;

  const date = new Date(Date.UTC(
    year, Number(match[2]) - 1, Number(match[3]),
    Number(match[4]), Number(match[5]), Number(match[6] || 0)
  ));

  // Certificates normally end with "Z" (UTC). Adjust if an offset is given.
  const zone = match[7];
  if (zone && zone !== 'Z') {
    const sign = zone[0] === '-' ? 1 : -1;
    const minutes = Number(zone.slice(1, 3)) * 60 + Number(zone.slice(-2));
    date.setTime(date.getTime() + sign * minutes * 60000);
  }
  return date;
}

/* ---------- step 2: read the pieces of the certificate ------------------- */

/**
 * A Name looks like: SEQUENCE of SET of SEQUENCE { OID, value }.
 * We join the parts with commas, e.g. "CN=example.com, O=Example, C=US".
 */
function readName(bytes, block) {
  const parts = [];
  readChildren(bytes, block).forEach((rdn) => {
    readChildren(bytes, rdn).forEach((attribute) => {
      const fields = readChildren(bytes, attribute);
      if (fields.length < 2) return;
      const label = ATTRIBUTE_NAMES[readOid(bytes, fields[0])] || readOid(bytes, fields[0]);
      parts.push(label + '=' + readText(bytes, fields[1]).trim());
    });
  });
  return parts.join(', ');
}

/** Pull the Common Name out of a name string, if there is one. */
function commonName(name) {
  const match = /(?:^|, )CN=([^,]+)/.exec(name);
  return match ? match[1] : '';
}

/** Read a certificate (already DER bytes) and return the details we show. */
function parseDer(bytes) {
  const certificate = readBlock(bytes, 0);
  if (certificate.tag !== 0x30) {
    throw new CertificateError('This file does not look like a certificate. Please choose a .cer, .crt or .pem certificate file.');
  }
  const tbs = readChildren(bytes, certificate)[0];
  const fields = readChildren(bytes, tbs);
  let index = 0;

  // The version is optional: [0] EXPLICIT INTEGER. Without it the cert is v1.
  let version = 0;
  if (fields[index].tag === 0xa0) {
    version = bytes[readChildren(bytes, fields[index])[0].valueStart];
    index += 1;
  }

  const serial = fields[index]; index += 1;
  const signatureAlgorithm = fields[index]; index += 1; // unused, kept for clarity
  const issuer = fields[index]; index += 1;
  const validity = fields[index]; index += 1;
  const subject = fields[index];

  const [notBeforeBlock, notAfterBlock] = readChildren(bytes, validity);
  const serialHex = readHex(bytes, serial);

  return {
    version: VERSION_NAMES[version] || 'v' + (version + 1),
    serialNumber: serialHex,
    subject: readName(bytes, subject),
    commonName: commonName(readName(bytes, subject)),
    issuer: readName(bytes, issuer),
    notBefore: readTime(bytes, notBeforeBlock),
    notAfter: readTime(bytes, notAfterBlock),
  };
}

/* ---------- step 3: accept either PEM (text) or DER (binary) ------------- */

/** Base64 -> bytes. */
function base64ToBytes(base64) {
  let binary;
  try {
    binary = global.atob(base64);
  } catch (error) {
    throw new CertificateError('The text inside the file is not valid base64 data.');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Is this file PEM text or raw DER binary? */
function looksLikePem(bytes) {
  const head = new TextDecoder('iso-8859-1').decode(bytes.subarray(0, 40));
  return head.includes('-----BEGIN');
}

/**
 * Find the "BEGIN X" label of a PEM file, e.g. "CERTIFICATE".
 * The label lets us give a helpful message for private keys and requests.
 */
function pemLabel(text) {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----/.exec(text);
  return match ? match[1] : '';
}

function parsePemText(text) {
  const label = pemLabel(text);
  if (label !== 'CERTIFICATE' && label !== 'X509 CERTIFICATE' && label !== 'TRUSTED CERTIFICATE') {
    const readable = {
      'PRIVATE KEY': 'a private key',
      'RSA PRIVATE KEY': 'a private key',
      'EC PRIVATE KEY': 'a private key',
      'CERTIFICATE REQUEST': 'a certificate signing request, not a certificate',
      'PKCS7': 'a PKCS#7 / bundle file, not a single certificate',
    }[label];
    throw new CertificateError(
      readable
        ? 'This file contains ' + readable + '. Please choose a certificate file (.cer, .crt or .pem).'
        : 'No certificate was found inside this file. It should start with "-----BEGIN CERTIFICATE-----".'
    );
  }
  const body = text
    .replace(/-----(BEGIN|END)[^-]+-----/g, '')
    .replace(/\s+/g, '');
  if (!body) throw new CertificateError('The certificate file appears to be empty.');
  return base64ToBytes(body);
}

/**
 * The public entry point: give it a Uint8Array (or ArrayBuffer) from a file
 * and get back { version, serialNumber, subject, commonName, issuer,
 * notBefore, notAfter }.
 */
function parseCertificate(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length === 0) throw new CertificateError('The file is empty.');

  try {
    // Need both forms because the label check needs text, but a DER file is binary.
    return looksLikePem(bytes)
      ? parseDer(parsePemText(new TextDecoder('iso-8859-1').decode(bytes)))
      : parseDer(bytes);
  } catch (error) {
    if (error instanceof CertificateError) throw error;
    throw new CertificateError('This file could not be read as a certificate. It may be damaged or in another format.');
  }
}

/* Expose the parser to the page (and to Node when testing). */
global.CertificateParser = {
  CertificateError: CertificateError,
  parseCertificate: parseCertificate,
};

})(typeof globalThis !== 'undefined' ? globalThis : this);

