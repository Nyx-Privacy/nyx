import { pubkeyToFrPair } from "../utxo/note.js";
import { buildPoseidon } from "circomlibjs";

let cached: any = null;
async function p(): Promise<any> {
  if (!cached) cached = await buildPoseidon();
  return cached;
}

/** PairVK = Poseidon5(mvk, base_lo, base_hi, quote_lo, quote_hi) */
export async function deriveViewingKeyForPair(
  mvk: bigint,
  baseMint: Uint8Array,
  quoteMint: Uint8Array,
): Promise<bigint> {
  const [bLo, bHi] = pubkeyToFrPair(baseMint);
  const [qLo, qHi] = pubkeyToFrPair(quoteMint);
  const ps = await p();
  const out = ps([mvk, bLo, bHi, qLo, qHi]);
  return ps.F.toObject(out);
}

/** MonthlyVK = Poseidon2(Poseidon2(pair_vk, year), month) */
export async function deriveMonthlyViewingKey(
  pairVk: bigint,
  year: bigint,
  month: bigint,
): Promise<bigint> {
  const ps = await p();
  const yearly = ps.F.toObject(ps([pairVk, year]));
  return ps.F.toObject(ps([yearly, month]));
}
