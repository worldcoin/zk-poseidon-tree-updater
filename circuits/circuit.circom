pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "./merkletreeupdater.circom";

template PoseidonTreeUpdate(n_levels, batch_size) {
    //// CONSTANTS
    var LEAVES_PER_NODE = 5;
    var LEAVES_PER_PATH_LEVEL = LEAVES_PER_NODE - 1;
    var BITS_IDENTITY_COMMITMENT = 256;
    var BITS_ROOT = 256;
    var SHA_BITS = 256;
    var MAX_DEPTH = 32;

    //// INPUTS
    signal input path_elements[batch_size][n_levels][LEAVES_PER_PATH_LEVEL];
    signal input roots[batch_size + 1];

    // following inputs will be hashed
    signal input start_leaf_idx;
    signal input pre_root;
    signal input post_root;
    signal input identity_commitment[batch_size];

    //// OUTPUTS
    signal output hashed_inputs;

    //// COMPONENTS
    component mtu[batch_size];
    component n2b_identity_path_index[batch_size];
    component n2b_identity_commitment[batch_size]; 
    component n2b_start_leaf_idx = Num2Bits(MAX_DEPTH);
    component n2b_pre_root = Num2Bits(BITS_ROOT);
    component n2b_post_root = Num2Bits(BITS_ROOT);
    component b2n_hashed_inputs = Bits2Num(SHA_BITS);

    var hash_input_bits = BITS_IDENTITY_COMMITMENT * batch_size + BITS_ROOT * 2 + MAX_DEPTH;
    component sha256_hasher = Sha256(hash_input_bits);
    
    //// MAIN

    var b;
    var i;
    var j;
    var offset = 0;

    // create MerkleTreeUpdaters
    for (b=0; b < batch_size; b++){
        mtu[b] = MerkleTreeUpdater(n_levels, LEAVES_PER_PATH_LEVEL);
        mtu[b].identity_commitment <== identity_commitment[b];

        n2b_identity_path_index[b] = Num2Bits(n_levels); 
        n2b_identity_path_index[b].in <== start_leaf_idx + b;

        for (i = 0; i < n_levels; i++) {
            for (j = 0; j < LEAVES_PER_PATH_LEVEL; j++) {
                mtu[b].path_elements[i][j] <== path_elements[b][i][j];
            }
            mtu[b].identity_path_index[i] <== n2b_identity_path_index[b].out[i];
        }
        
        // verify roots
        roots[b] === mtu[b].pre_root;
        roots[b + 1] === mtu[b].post_root;
    }

    // check input root and resulting root
    pre_root === roots[0];
    post_root === roots[batch_size];

    //// HASH INPUTS

    // start_leaf_idx
    n2b_start_leaf_idx.in <== start_leaf_idx;
    for (i = 0; i < MAX_DEPTH; i++) {
        sha256_hasher.in[offset + MAX_DEPTH - 1 - i] <== n2b_start_leaf_idx.out[i];
    }
    offset = offset + MAX_DEPTH;

    // pre-root
    n2b_pre_root.in <== pre_root;
    for (i = 0; i < BITS_ROOT; i++) {
        sha256_hasher.in[offset + BITS_ROOT - 1 - i] <== n2b_pre_root.out[i];
    }
    offset = offset + BITS_ROOT;

    // post-root
    n2b_post_root.in <== post_root;
    for (i = 0; i < BITS_ROOT; i++) {
        sha256_hasher.in[offset + BITS_ROOT - 1 - i] <== n2b_post_root.out[i];
    }
    offset = offset + BITS_ROOT;

    // identity_commitments
    for (b=0; b < batch_size; b++){
        n2b_identity_commitment[b] = Num2Bits(BITS_IDENTITY_COMMITMENT);
        n2b_identity_commitment[b].in <== identity_commitment[b];
    }

    for (b=0; b < batch_size; b++){
        for (i = 0; i < BITS_IDENTITY_COMMITMENT; i++) {
            sha256_hasher.in[offset + BITS_IDENTITY_COMMITMENT - 1 - i] <== n2b_identity_commitment[b].out[i];
        }
        offset = offset + BITS_IDENTITY_COMMITMENT;
    }

    // calc sha256
    for (i = 0; i < SHA_BITS; i++) {
        b2n_hashed_inputs.in[i] <== sha256_hasher.out[SHA_BITS- 1 - i];
    }

    // output hash
    hashed_inputs <== b2n_hashed_inputs.out;
}

component main = PoseidonTreeUpdate(10, 2);