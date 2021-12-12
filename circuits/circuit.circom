pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./merkletreeupdater.circom";

template PoseidonTreeUpdate(n_levels, batch_size) {
    var LEAVES_PER_NODE = 5;
    var LEAVES_PER_PATH_LEVEL = LEAVES_PER_NODE - 1;

    signal input identity_path_index[batch_size][n_levels];
    signal input path_elements[batch_size][n_levels][LEAVES_PER_PATH_LEVEL];
    signal input roots[batch_size + 1];
    signal input identity_commitment[batch_size];

    signal output pre_root;
    signal output post_root;

    component mtu[batch_size];

    for (var b=0; b < batch_size; b++){
        mtu[b] = MerkleTreeUpdater(n_levels, LEAVES_PER_PATH_LEVEL);
        mtu[b].identity_commitment <== identity_commitment[b];

        for (var i = 0; i < n_levels; i++) {
            for (var j = 0; j < LEAVES_PER_PATH_LEVEL; j++) {
                mtu[b].path_elements[i][j] <== path_elements[b][i][j];
            }
            mtu[b].identity_path_index[i] <== identity_path_index[b][i];
        }
        
        // verify pre and post roots
        roots[b] === mtu[b].pre_root;
        roots[b + 1] === mtu[b].post_root;
    }

    pre_root <== roots[0];
    post_root <== roots[batch_size];
}

component main {public [identity_commitment]} = PoseidonTreeUpdate(10, 2);