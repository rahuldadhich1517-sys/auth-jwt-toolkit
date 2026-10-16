/**
 * Options for decodeJwt.
 */
export interface DecodeJwtOptions {
  /**
   * Maximum allowed token length in characters.
   * @default 65536
   */
  readonly maxTokenLength?: number;
}

/**
 * Result returned by decodeJwt.
 */
export interface DecodedJwt<
  Header extends object = Record<string, unknown>,
  Payload extends object = Record<string, unknown>
> {
  readonly header: Header;
  readonly payload: Payload;
  readonly signature: string;
  readonly segments: {
    readonly header: string;
    readonly payload: string;
    readonly signature: string;
  };
}
