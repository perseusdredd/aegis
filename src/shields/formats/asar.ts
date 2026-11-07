import { createHash } from "node:crypto";
import { posix } from "node:path";

export class UnsupportedAsarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedAsarError";
  }
}

export interface AsarFileIntegrity {
  readonly algorithm: "SHA256";
  readonly hash: string;
  readonly blockSize: number;
  readonly blocks: readonly string[];
}

export interface AsarFileEntry {
  readonly offset: string;
  readonly size: number;
  readonly unpacked?: boolean;
  readonly executable?: boolean;
  readonly integrity?: AsarFileIntegrity;
}

export interface AsarUnpackedFileNode {
  readonly size: number;
  readonly unpacked: true;
  readonly executable?: boolean;
  readonly integrity?: AsarFileIntegrity;
}

export interface AsarLinkNode {
  readonly link: string;
}

export interface AsarDirectoryNode {
  readonly files: Record<string, AsarHeaderNode>;
}

export type AsarHeaderNode =
  | AsarFileEntry
  | AsarUnpackedFileNode
  | AsarLinkNode
  | AsarDirectoryNode;

export type AsarNode = AsarHeaderNode;

export interface VirtualAsarFile {
  readonly relativePath: string;
  readonly content: Buffer;
  readonly executable?: boolean;
  readonly unpacked?: boolean;
  readonly link?: string;
  readonly size?: number;
}

export interface AsarValidationOptions {
  readonly allowUnpacked?: boolean;
  readonly allowLinks?: boolean;
  readonly rejectUnpacked?: boolean;
  readonly rejectLinks?: boolean;
}

const ASAR_BLOCK_SIZE = 4 * 1024 * 1024;
const ALLOWED_NODE_KEYS = new Set([
  "files",
  "link",
  "size",
  "offset",
  "unpacked",
  "executable",
  "integrity",
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isDirectoryNode(node: AsarHeaderNode): node is AsarDirectoryNode {
  return isPlainObject(node) && isPlainObject((node as AsarDirectoryNode).files);
}

function validateEntrySegment(segment: string): void {
  if (
    segment.length === 0 ||
    segment === "." ||
    segment === ".." ||
    segment.includes("/") ||
    segment.includes("\\") ||
    segment.includes("\0")
  ) {
    throw new UnsupportedAsarError(`Invalid ASAR path segment: ${JSON.stringify(segment)}`);
  }
}

function validateRelativeLinkTarget(relativePath: string, linkTarget: unknown): string {
  if (
    typeof linkTarget !== "string" ||
    linkTarget.length === 0 ||
    linkTarget.includes("\0") ||
    linkTarget.includes("\\") ||
    posix.isAbsolute(linkTarget)
  ) {
    throw new UnsupportedAsarError(
      `Invalid or absolute ASAR link target at ${relativePath}: ${String(linkTarget)}`,
    );
  }

  const parentSegments = relativePath.split("/").slice(0, -1).filter(Boolean);
  let depth = parentSegments.length;
  const targetSegments = linkTarget.split("/");
  for (const seg of targetSegments) {
    if (seg === "" || seg === ".") {
      continue;
    }
    if (seg === "..") {
      depth -= 1;
      if (depth < 0) {
        throw new UnsupportedAsarError(
          `Escaping ASAR link target at ${relativePath}: ${linkTarget}`,
        );
      }
    } else {
      depth += 1;
    }
  }

  const parentDir = posix.dirname(relativePath);
  const resolved = posix.normalize(
    parentDir === "." ? linkTarget : posix.join(parentDir, linkTarget),
  );
  if (
    resolved === "" ||
    resolved === "." ||
    resolved === ".." ||
    resolved.startsWith("../") ||
    resolved.startsWith("/")
  ) {
    throw new UnsupportedAsarError(
      `Escaping or invalid ASAR link target at ${relativePath}: ${linkTarget}`,
    );
  }

  return linkTarget;
}

function computeAsarIntegrity(content: Buffer): AsarFileIntegrity {
  const hash = createHash("sha256").update(content).digest("hex");
  const blocks: string[] = [];
  if (content.length === 0) {
    blocks.push(createHash("sha256").update(Buffer.alloc(0)).digest("hex"));
  } else {
    for (let offset = 0; offset < content.length; offset += ASAR_BLOCK_SIZE) {
      const slice = content.subarray(offset, Math.min(content.length, offset + ASAR_BLOCK_SIZE));
      blocks.push(createHash("sha256").update(slice).digest("hex"));
    }
  }
  return {
    algorithm: "SHA256",
    hash,
    blockSize: ASAR_BLOCK_SIZE,
    blocks,
  };
}

/**
 * Unpacks an Electron `.asar` archive buffer into an in-memory array of virtual files.
 * Follows Chromium Pickle framing used by `@electron/asar` and `morluto/rea`.
 * Strictly validates node shapes, offsets, sizes, bounds, unpacked entries, and link targets.
 */
export function unpackAsarBuffer(
  asarBytes: Buffer,
  options: AsarValidationOptions = {},
): readonly VirtualAsarFile[] {
  if (asarBytes.length < 16) {
    throw new UnsupportedAsarError(
      "Invalid ASAR archive: buffer shorter than 16-byte pickle header",
    );
  }
  const sizePicklePayload = asarBytes.readUInt32LE(0);
  if (sizePicklePayload !== 4) {
    throw new UnsupportedAsarError(
      `Invalid ASAR header: expected outer pickle payload size 4, got ${sizePicklePayload}`,
    );
  }
  const headerSize = asarBytes.readUInt32LE(4);
  const innerPickleSize = asarBytes.readUInt32LE(8);
  const jsonStringSize = asarBytes.readUInt32LE(12);
  const dataOffsetBase = 8 + headerSize;

  if (
    headerSize < 8 ||
    innerPickleSize < 4 ||
    jsonStringSize === 0 ||
    16 + jsonStringSize > dataOffsetBase ||
    16 + jsonStringSize > asarBytes.length ||
    dataOffsetBase > asarBytes.length
  ) {
    throw new UnsupportedAsarError("Invalid ASAR archive: header exceeds buffer bounds");
  }

  const headerJson = asarBytes.subarray(16, 16 + jsonStringSize).toString("utf8");
  let rootRaw: unknown;
  try {
    rootRaw = JSON.parse(headerJson);
  } catch {
    throw new UnsupportedAsarError("Invalid ASAR archive: malformed JSON header");
  }

  if (
    !isPlainObject(rootRaw) ||
    !isPlainObject(rootRaw.files) ||
    "size" in rootRaw ||
    "offset" in rootRaw ||
    "link" in rootRaw ||
    "unpacked" in rootRaw
  ) {
    throw new UnsupportedAsarError("Invalid ASAR archive: root must be a directory node");
  }

  const rejectUnpacked =
    options.rejectUnpacked === true || options.allowUnpacked === false;
  const rejectLinks =
    options.rejectLinks === true || options.allowLinks === false;

  const files: VirtualAsarFile[] = [];

  const walkDirectory = (dirFiles: Record<string, unknown>, prefix: string): void => {
    for (const [name, child] of Object.entries(dirFiles)) {
      validateEntrySegment(name);
      const nextPath = prefix ? `${prefix}/${name}` : name;

      if (!isPlainObject(child)) {
        throw new UnsupportedAsarError(`Malformed ASAR node at ${nextPath}`);
      }

      const childKeys = Object.keys(child);
      if (childKeys.length === 0) {
        throw new UnsupportedAsarError(`Empty ASAR node at ${nextPath}`);
      }
      for (const k of childKeys) {
        if (!ALLOWED_NODE_KEYS.has(k)) {
          throw new UnsupportedAsarError(
            `Unknown or unsupported ASAR node property '${k}' at ${nextPath}`,
          );
        }
      }

      const hasFiles = child.files !== undefined;
      const hasLink = child.link !== undefined;
      const hasSize = child.size !== undefined;
      const hasOffset = child.offset !== undefined;
      const isUnpacked = child.unpacked === true;

      if (hasFiles) {
        if (
          !isPlainObject(child.files) ||
          hasLink ||
          hasSize ||
          hasOffset ||
          child.unpacked !== undefined ||
          child.executable !== undefined
        ) {
          throw new UnsupportedAsarError(`Malformed ASAR directory node at ${nextPath}`);
        }
        walkDirectory(child.files, nextPath);
        continue;
      }

      if (hasLink) {
        if (hasSize || hasOffset || child.unpacked !== undefined || child.executable !== undefined) {
          throw new UnsupportedAsarError(`Conflicting ASAR link node properties at ${nextPath}`);
        }
        const validatedLink = validateRelativeLinkTarget(nextPath, child.link);
        if (rejectLinks) {
          throw new UnsupportedAsarError(
            `ASAR link node at ${nextPath} requires link-preserving pipeline`,
          );
        }
        files.push({
          relativePath: nextPath,
          content: Buffer.alloc(0),
          link: validatedLink,
        });
        continue;
      }

      if (child.executable !== undefined && typeof child.executable !== "boolean") {
        throw new UnsupportedAsarError(`Invalid ASAR executable flag at ${nextPath}`);
      }

      if (isUnpacked) {
        if (
          typeof child.size !== "number" ||
          !Number.isSafeInteger(child.size) ||
          child.size < 0
        ) {
          throw new UnsupportedAsarError(`Invalid ASAR unpacked file size at ${nextPath}`);
        }
        if (rejectUnpacked) {
          throw new UnsupportedAsarError(
            `ASAR unpacked node at ${nextPath} requires companion .asar.unpacked directory preservation`,
          );
        }
        files.push({
          relativePath: nextPath,
          content: Buffer.alloc(0),
          unpacked: true,
          size: child.size,
          ...(child.executable ? { executable: true } : {}),
        });
        continue;
      }

      if (child.unpacked !== undefined && child.unpacked !== false) {
        throw new UnsupportedAsarError(`Invalid ASAR unpacked property at ${nextPath}`);
      }

      if (
        typeof child.size !== "number" ||
        !Number.isSafeInteger(child.size) ||
        child.size < 0
      ) {
        throw new UnsupportedAsarError(
          `Invalid ASAR file size at ${nextPath}: ${String(child.size)}`,
        );
      }

      if (
        typeof child.offset !== "string" ||
        !/^(0|[1-9]\d*)$/.test(child.offset)
      ) {
        throw new UnsupportedAsarError(
          `Invalid ASAR file offset at ${nextPath}: ${String(child.offset)}`,
        );
      }

      const offset = Number(child.offset);
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new UnsupportedAsarError(
          `Unsafe ASAR file offset at ${nextPath}: ${child.offset}`,
        );
      }

      const start = dataOffsetBase + offset;
      const end = start + child.size;
      if (
        !Number.isSafeInteger(start) ||
        !Number.isSafeInteger(end) ||
        start < dataOffsetBase ||
        end < start ||
        end > asarBytes.length
      ) {
        throw new UnsupportedAsarError(`ASAR file offset/size out of bounds for ${nextPath}`);
      }

      files.push({
        relativePath: nextPath,
        content: Buffer.from(asarBytes.subarray(start, end)),
        size: child.size,
        ...(child.executable ? { executable: true } : {}),
      });
    }
  };

  walkDirectory(rootRaw.files, "");
  return files;
}

/**
 * Validates an ASAR archive buffer and returns its virtual entries.
 */
export function validateAsarBuffer(
  bytes: Buffer,
  options: { readonly allowUnpacked?: boolean; readonly allowLinks?: boolean } = {},
): readonly VirtualAsarFile[] {
  return unpackAsarBuffer(bytes, {
    rejectUnpacked: options.allowUnpacked === false,
    rejectLinks: options.allowLinks === false,
  });
}

/**
 * Validates an ASAR archive before standalone protection.
 * Fails closed (`UnsupportedAsarError`) when the archive contains external `unpacked: true`
 * entries unless `allowUnpacked: true` (companion `.asar.unpacked` synchronization) is enabled.
 */
export function validateAsarProtectionInput(
  bytes: Buffer,
  options: { readonly allowUnpacked?: boolean; readonly allowLinks?: boolean } = {},
): readonly VirtualAsarFile[] {
  return unpackAsarBuffer(bytes, {
    rejectUnpacked: options.allowUnpacked !== true,
    rejectLinks: options.allowLinks === false,
  });
}

/**
 * Packs an array of virtual files into a valid Electron `.asar` archive buffer
 * with full SHA-256 block integrity metadata, preserving `executable`, `unpacked`, and `link` nodes.
 */
export function packAsarBuffer(files: readonly VirtualAsarFile[]): Buffer {
  const root: AsarDirectoryNode = { files: {} };
  const payloadChunks: Buffer[] = [];
  let currentOffset = 0;

  for (const file of files) {
    if (file.relativePath.includes("\\") || file.relativePath.includes("\0")) {
      throw new UnsupportedAsarError(`Invalid ASAR file relativePath: ${file.relativePath}`);
    }
    const rawSegments = file.relativePath.replace(/^\/+/, "").split("/");
    if (rawSegments.length === 0 || (rawSegments.length === 1 && rawSegments[0] === "")) {
      continue;
    }
    for (const seg of rawSegments) {
      validateEntrySegment(seg);
    }

    const normalizedPath = rawSegments.join("/");
    let currentDir = root;
    for (let i = 0; i < rawSegments.length - 1; i++) {
      const seg = rawSegments[i]!;
      const existing = currentDir.files[seg];
      if (!existing) {
        const nextDir: AsarDirectoryNode = { files: {} };
        currentDir.files[seg] = nextDir;
        currentDir = nextDir;
      } else if (isDirectoryNode(existing)) {
        currentDir = existing;
      } else {
        throw new UnsupportedAsarError(
          `ASAR path conflict at ${seg}: cannot create directory over non-directory entry`,
        );
      }
    }

    const leafName = rawSegments[rawSegments.length - 1]!;
    if (file.link !== undefined) {
      const validatedLink = validateRelativeLinkTarget(normalizedPath, file.link);
      currentDir.files[leafName] = {
        link: validatedLink,
      };
      continue;
    }

    if (file.unpacked === true) {
      const unpackedSize = file.size !== undefined ? file.size : file.content.length;
      if (!Number.isSafeInteger(unpackedSize) || unpackedSize < 0) {
        throw new UnsupportedAsarError(`Invalid unpacked file size for ${normalizedPath}`);
      }
      currentDir.files[leafName] = {
        size: unpackedSize,
        unpacked: true,
        ...(file.executable ? { executable: true } : {}),
        ...(file.content.length > 0 ? { integrity: computeAsarIntegrity(file.content) } : {}),
      };
      continue;
    }

    currentDir.files[leafName] = {
      offset: String(currentOffset),
      size: file.content.length,
      ...(file.executable ? { executable: true } : {}),
      integrity: computeAsarIntegrity(file.content),
    };
    payloadChunks.push(file.content);
    currentOffset += file.content.length;
  }

  const jsonBytes = Buffer.from(JSON.stringify(root), "utf8");
  const jsonStringSize = jsonBytes.length;
  // Align JSON bytes to 4-byte boundary per Chromium Pickle string framing
  const alignedJsonSize = Math.ceil(jsonStringSize / 4) * 4;
  const innerPickleSize = alignedJsonSize + 4;
  const headerSize = innerPickleSize + 4;

  const headerBuffer = Buffer.alloc(8 + headerSize, 0);
  headerBuffer.writeUInt32LE(4, 0);
  headerBuffer.writeUInt32LE(headerSize, 4);
  headerBuffer.writeUInt32LE(innerPickleSize, 8);
  headerBuffer.writeUInt32LE(jsonStringSize, 12);
  jsonBytes.copy(headerBuffer, 16);

  return Buffer.concat([headerBuffer, ...payloadChunks]);
}
