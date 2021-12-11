pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "./merkletreeupdater.circom";

template PoseidonTreeUpdate(n_levels, batch_size) {
    var LEAVES_PER_NODE = 5;
    var LEAVES_PER_PATH_LEVEL = LEAVES_PER_NODE - 1;

    signal input identity_path_index[batch_size][n_levels];
    signal input path_elements[batch_size][n_levels][LEAVES_PER_PATH_LEVEL];
    signal input identity_commitment[batch_size];

    signal output root[batch_size*2];

    var i;
    var j;
    var b;

    component mtu[batch_size];

    for (b=0; b<batch_size; b++){
        mtu[b] = MerkleTreeUpdater(n_levels, LEAVES_PER_PATH_LEVEL);
        mtu[b].identity_commitment <== identity_commitment[b];

        for (i = 0; i < n_levels; i++) {
            for (j = 0; j < LEAVES_PER_PATH_LEVEL; j++) {
                mtu[b].path_elements[i][j] <== path_elements[b][i][j];
            }
            mtu[b].identity_path_index[i] <== identity_path_index[b][i];
        }
        
        // verify pre and post roots
        root[b * 2] <== mtu[b].pre_root;
        root[b * 2 + 1] <== mtu[b].post_root;
    }
}

component main = PoseidonTreeUpdate(10, 2);