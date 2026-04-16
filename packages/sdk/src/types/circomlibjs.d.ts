declare module "circomlibjs" {
  export interface PoseidonField {
    e(x: bigint | number | string): Uint8Array;
    toObject(x: Uint8Array): bigint;
  }
  export interface PoseidonFn {
    (inputs: Array<bigint | number | string | Uint8Array>): Uint8Array;
    F: PoseidonField;
  }
  export function buildPoseidon(): Promise<PoseidonFn>;
}
