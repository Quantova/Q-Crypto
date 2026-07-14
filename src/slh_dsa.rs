//! SLH-DSA (FIPS 205) - stateless hash based signatures. Conservative signature option; backs the

#![allow(dead_code)]

use crate::sha3::shake256;

// Parameter set SLH-DSA-SHAKE-192s (FIPS 205, Table 2).
const N: usize = 24; // security parameter in bytes
const H: usize = 63; // total hypertree height
const D: usize = 7; // number of hypertree layers
const HP: usize = H / D; // height of a single XMSS tree (h', = 9)
const A: usize = 14; // height of a FORS tree
const K: usize = 17; // number of FORS trees
const LGW: usize = 4; // log2 of the Winternitz parameter
const W: u32 = 1 << LGW; // Winternitz parameter (16)
const LEN1: usize = (8 * N + LGW - 1) / LGW; // 48
const LEN2: usize = 3; // checksum chain count
const LEN: usize = LEN1 + LEN2; // 51 WOTS+ chains

// Message digest split produced by H_msg (FIPS 205 Algorithm 19).
const MD_BYTES: usize = (K * A + 7) / 8; // 30, feeds the FORS message indices
const TREE_BYTES: usize = (H - HP + 7) / 8; // 7, feeds the hypertree address
const LEAF_BYTES: usize = (HP + 7) / 8; // 2, feeds the leaf address
const DIGEST_BYTES: usize = MD_BYTES + TREE_BYTES + LEAF_BYTES; // 39

// One XMSS signature is a WOTS+ signature followed by its authentication path.
const XMSS_SIG_BYTES: usize = (LEN + HP) * N; // 1440
const FORS_SIG_BYTES: usize = K * (1 + A) * N; // 6120

/// Public key length in bytes (PK.seed followed by PK.root).
pub const PUBLIC_KEY_BYTES: usize = 2 * N; // 48
/// Secret key length in bytes (SK.seed, SK.prf, PK.seed, PK.root).
pub const SECRET_KEY_BYTES: usize = 4 * N; // 96
/// Signature length in bytes.
pub const SIGNATURE_BYTES: usize = N + FORS_SIG_BYTES + D * XMSS_SIG_BYTES; // 16224

// ADRS type words (FIPS 205 section 4.2).
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

// The full 32-byte address used by the SHAKE instantiation.
#[derive(Clone)]
struct Adrs([u8; 32]);

impl Adrs {
    fn new() -> Self {
        Adrs([0u8; 32])
    }

    fn set_layer(&mut self, layer: u32) {
        self.0[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    fn set_tree(&mut self, tree: u64) {
        // The tree address is the 12-byte field at offset 4; the high 4 bytes are always zero here.
        self.0[4..8].copy_from_slice(&[0u8; 4]);
        self.0[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type_and_clear(&mut self, kind: u32) {
        self.0[16..20].copy_from_slice(&kind.to_be_bytes());
        self.0[20..32].copy_from_slice(&[0u8; 12]);
    }

    fn set_key_pair(&mut self, i: u32) {
        self.0[20..24].copy_from_slice(&i.to_be_bytes());
    }

    fn key_pair(&self) -> u32 {
        u32::from_be_bytes(self.0[20..24].try_into().unwrap())
    }

    fn set_chain(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }

    fn set_hash(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }

    fn set_tree_height(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }

    fn set_tree_index(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }

    fn tree_index(&self) -> u32 {
        u32::from_be_bytes(self.0[28..32].try_into().unwrap())
    }
}

// PRF(PK.seed, SK.seed, ADRS) = SHAKE256(PK.seed || ADRS || SK.seed, 8n).
fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> [u8; N] {
    let mut input = [0u8; N + 32 + N];
    input[..N].copy_from_slice(pk_seed);
    input[N..N + 32].copy_from_slice(&adrs.0);
    input[N + 32..].copy_from_slice(sk_seed);
    let mut out = [0u8; N];
    shake256(&input, &mut out);
    out
}

// F, H and T_l all reduce to SHAKE256(PK.seed || ADRS || message, 8n).
fn hash_n(pk_seed: &[u8], adrs: &Adrs, message: &[u8]) -> [u8; N] {
    let mut input = Vec::with_capacity(N + 32 + message.len());
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(&adrs.0);
    input.extend_from_slice(message);
    let mut out = [0u8; N];
    shake256(&input, &mut out);
    out
}

// PRF_msg(SK.prf, opt_rand, M) = SHAKE256(SK.prf || opt_rand || M, 8n).
fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], message: &[u8]) -> [u8; N] {
    let mut input = Vec::with_capacity(N + N + message.len());
    input.extend_from_slice(sk_prf);
    input.extend_from_slice(opt_rand);
    input.extend_from_slice(message);
    let mut out = [0u8; N];
    shake256(&input, &mut out);
    out
}

// H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M, 8m).
fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], message: &[u8]) -> [u8; DIGEST_BYTES] {
    let mut input = Vec::with_capacity(N + N + N + message.len());
    input.extend_from_slice(r);
    input.extend_from_slice(pk_seed);
    input.extend_from_slice(pk_root);
    input.extend_from_slice(message);
    let mut out = [0u8; DIGEST_BYTES];
    shake256(&input, &mut out);
    out
}

// Big-endian byte string to integer (FIPS 205 toInt).
fn to_int(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for &b in bytes {
        value = (value << 8) | b as u64;
    }
    value
}

// Split a byte string into out_len integers of b bits each, most significant bit first (base_2b).
fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(out_len);
    let mut pos = 0usize;
    let mut bits = 0usize;
    let mut total = 0u64;
    let mask = (1u64 << b) - 1;
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | x[pos] as u64;
            pos += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & mask) as u32);
    }
    out
}

// A WOTS+ hash chain from position start for the given number of steps.
fn chain(input: &[u8; N], start: u32, steps: u32, pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = *input;
    for j in start..start + steps {
        adrs.set_hash(j);
        tmp = hash_n(pk_seed, adrs, &tmp);
    }
    tmp
}

// The WOTS+ message plus its checksum, expanded to LEN base-w digits.
fn wots_digits(message: &[u8; N]) -> [u32; LEN] {
    let mut digits = [0u32; LEN];
    let base = base_2b(message, LGW, LEN1);
    let mut csum = 0u32;
    for i in 0..LEN1 {
        digits[i] = base[i];
        csum += W - 1 - base[i];
    }
    csum <<= (8 - ((LEN2 * LGW) % 8)) % 8;
    let csum_bytes = (LEN2 * LGW + 7) / 8;
    let be = csum.to_be_bytes();
    let checksum = base_2b(&be[4 - csum_bytes..], LGW, LEN2);
    for i in 0..LEN2 {
        digits[LEN1 + i] = checksum[i];
    }
    digits
}

// WOTS+ public key: the T hash of all chain endpoints.
fn wots_pk_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    let mut tmp = Vec::with_capacity(LEN * N);
    for i in 0..LEN {
        sk_adrs.set_chain(i as u32);
        let sk = prf(pk_seed, sk_seed, &sk_adrs);
        adrs.set_chain(i as u32);
        tmp.extend_from_slice(&chain(&sk, 0, W - 1, pk_seed, adrs));
    }
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair(adrs.key_pair());
    hash_n(pk_seed, &pk_adrs, &tmp)
}

// WOTS+ signature for an n-byte message.
fn wots_sign(message: &[u8; N], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let digits = wots_digits(message);
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    let mut sig = Vec::with_capacity(LEN * N);
    for i in 0..LEN {
        sk_adrs.set_chain(i as u32);
        let sk = prf(pk_seed, sk_seed, &sk_adrs);
        adrs.set_chain(i as u32);
        sig.extend_from_slice(&chain(&sk, 0, digits[i], pk_seed, adrs));
    }
    sig
}

// Recover a WOTS+ public key from a signature.
fn wots_pk_from_sig(sig: &[u8], message: &[u8; N], pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let digits = wots_digits(message);
    let mut tmp = Vec::with_capacity(LEN * N);
    for i in 0..LEN {
        adrs.set_chain(i as u32);
        let mut node = [0u8; N];
        node.copy_from_slice(&sig[i * N..(i + 1) * N]);
        tmp.extend_from_slice(&chain(&node, digits[i], W - 1 - digits[i], pk_seed, adrs));
    }
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_key_pair(adrs.key_pair());
    hash_n(pk_seed, &pk_adrs, &tmp)
}

// A node of an XMSS tree at height z and horizontal index i.
fn xmss_node(sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_key_pair(i);
        wots_pk_gen(sk_seed, pk_seed, adrs)
    } else {
        let left = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
        let right = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
        adrs.set_type_and_clear(TREE);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut pair = [0u8; 2 * N];
        pair[..N].copy_from_slice(&left);
        pair[N..].copy_from_slice(&right);
        hash_n(pk_seed, adrs, &pair)
    }
}

// An XMSS signature: the WOTS+ signature at the leaf plus the authentication path.
fn xmss_sign(
    message: &[u8; N],
    sk_seed: &[u8],
    idx: u32,
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let mut auth = Vec::with_capacity(HP * N);
    for j in 0..HP {
        let sibling = (idx >> j) ^ 1;
        auth.extend_from_slice(&xmss_node(sk_seed, sibling, j as u32, pk_seed, adrs));
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair(idx);
    let mut sig = wots_sign(message, sk_seed, pk_seed, adrs);
    sig.extend_from_slice(&auth);
    sig
}

// Recover an XMSS root from a signature and the leaf index.
fn xmss_pk_from_sig(
    idx: u32,
    xmss_sig: &[u8],
    message: &[u8; N],
    pk_seed: &[u8],
    adrs: &mut Adrs,
) -> [u8; N] {
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_key_pair(idx);
    let wots_sig = &xmss_sig[..LEN * N];
    let auth = &xmss_sig[LEN * N..];
    let mut node = wots_pk_from_sig(wots_sig, message, pk_seed, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for k in 0..HP {
        adrs.set_tree_height((k + 1) as u32);
        let sibling = &auth[k * N..(k + 1) * N];
        let mut pair = [0u8; 2 * N];
        if (idx >> k) & 1 == 0 {
            adrs.set_tree_index(adrs.tree_index() / 2);
            pair[..N].copy_from_slice(&node);
            pair[N..].copy_from_slice(sibling);
        } else {
            adrs.set_tree_index((adrs.tree_index() - 1) / 2);
            pair[..N].copy_from_slice(sibling);
            pair[N..].copy_from_slice(&node);
        }
        node = hash_n(pk_seed, adrs, &pair);
    }
    node
}

// A single FORS secret value.
fn fors_sk_gen(sk_seed: &[u8], pk_seed: &[u8], adrs: &Adrs, idx: u32) -> [u8; N] {
    let mut sk_adrs = adrs.clone();
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_key_pair(adrs.key_pair());
    sk_adrs.set_tree_index(idx);
    prf(pk_seed, sk_seed, &sk_adrs)
}

// A node of a FORS tree at height z and index i.
fn fors_node(sk_seed: &[u8], i: u32, z: u32, pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    if z == 0 {
        let sk = fors_sk_gen(sk_seed, pk_seed, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        hash_n(pk_seed, adrs, &sk)
    } else {
        let left = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
        let right = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);
        adrs.set_tree_height(z);
        adrs.set_tree_index(i);
        let mut pair = [0u8; 2 * N];
        pair[..N].copy_from_slice(&left);
        pair[N..].copy_from_slice(&right);
        hash_n(pk_seed, adrs, &pair)
    }
}

// A FORS signature: for each tree, the chosen secret value and its authentication path.
fn fors_sign(md: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let indices = base_2b(md, A, K);
    let mut sig = Vec::with_capacity(FORS_SIG_BYTES);
    for i in 0..K {
        let leaf = indices[i];
        let tree_base = (i as u32) << A;
        sig.extend_from_slice(&fors_sk_gen(sk_seed, pk_seed, adrs, tree_base + leaf));
        for j in 0..A {
            let sibling = (leaf >> j) ^ 1;
            let node = fors_node(
                sk_seed,
                (i as u32) * (1 << (A - j)) + sibling,
                j as u32,
                pk_seed,
                adrs,
            );
            sig.extend_from_slice(&node);
        }
    }
    sig
}

// Recover the FORS public key from a signature.
fn fors_pk_from_sig(sig_fors: &[u8], md: &[u8], pk_seed: &[u8], adrs: &mut Adrs) -> [u8; N] {
    let indices = base_2b(md, A, K);
    let elem = (1 + A) * N;
    let mut roots = Vec::with_capacity(K * N);
    for i in 0..K {
        let leaf = indices[i];
        let base = i * elem;
        adrs.set_tree_height(0);
        adrs.set_tree_index((i as u32) * (1 << A) + leaf);
        let mut node = hash_n(pk_seed, adrs, &sig_fors[base..base + N]);
        let auth = &sig_fors[base + N..base + elem];
        for j in 0..A {
            adrs.set_tree_height((j + 1) as u32);
            let sibling = &auth[j * N..(j + 1) * N];
            let mut pair = [0u8; 2 * N];
            if (leaf >> j) & 1 == 0 {
                adrs.set_tree_index(adrs.tree_index() / 2);
                pair[..N].copy_from_slice(&node);
                pair[N..].copy_from_slice(sibling);
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                pair[..N].copy_from_slice(sibling);
                pair[N..].copy_from_slice(&node);
            }
            node = hash_n(pk_seed, adrs, &pair);
        }
        roots.extend_from_slice(&node);
    }
    let mut pk_adrs = adrs.clone();
    pk_adrs.set_type_and_clear(FORS_ROOTS);
    pk_adrs.set_key_pair(adrs.key_pair());
    hash_n(pk_seed, &pk_adrs, &roots)
}
