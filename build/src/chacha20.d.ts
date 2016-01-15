export declare class Chacha20 {
    private input;
    constructor(key: Buffer, nonce: Buffer, counter?: number);
    update(raw: Buffer): Buffer;
    final(): Buffer;
    private quarterRound(x, a, b, c, d);
    private encrypt(dst, src, len);
}
