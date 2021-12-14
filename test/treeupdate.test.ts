const { generateMerkleProof } = require("@libsem/protocols");
const { ZkIdentity } = require("@libsem/identity");

import { MerkleProof } from "@libsem/types"
import { genProof, verifyProof } from "../src";
import * as ethers from "ethers";
import * as fs from "fs";
import * as path from "path";

jest.setTimeout(30*1000);

const BATCH_SIZE = 2;
const TREE_DEPTH = 10;
const ZERO_VALUE = BigInt(0)

describe('Proof test', () => {
    it("Should create proof", async () => {
        const commitments = []
        const premerkleProof: MerkleProof = generateMerkleProof(TREE_DEPTH, ZERO_VALUE, 5, [ZERO_VALUE], ZERO_VALUE)

        // const tmpproof: MerkleProof = generateMerkleProof(3, ZERO_VALUE, 2, [ZERO_VALUE], ZERO_VALUE);
        // console.log(tmpproof.pathElements);
        
        const identity_path_index = [];
        const path_elements = [];
        const identity_commitment = [];
        const roots = [premerkleProof.root];

        for (let i = 0; i < BATCH_SIZE; i++) {
            const identity = new ZkIdentity();
            const id_comm = identity.genIdentityCommitment();
    
            commitments.push(id_comm)
            const postmerkleProof: MerkleProof = generateMerkleProof(TREE_DEPTH, ZERO_VALUE, 5, commitments, id_comm)
    
            identity_path_index.push(postmerkleProof.indices)
            path_elements.push(postmerkleProof.pathElements)
            identity_commitment.push(id_comm)
            roots.push(postmerkleProof.root)
        }

        const start_leaf_idx = 0;
        const pre_root = roots[0];
        const post_root = roots[roots.length - 1];

        const grothInput = {
            start_leaf_idx,
            path_elements,
            roots,
            identity_commitment,
            pre_root,
            post_root
        };

        const wasmFilePath: string = path.join("./zkFiles", "circuit.wasm")
        const finalZkeyPath: string = path.join("./zkFiles", "circuit_final.zkey")
        const vkeyPath = path.join("./zkFiles", "verification_key.json")

        const fullProof = await genProof(grothInput, wasmFilePath, finalZkeyPath);

        let input = "0x";
        input += BigInt(0).toString(16).padStart(8, "0");
        input += BigInt(roots[0]).toString(16).padStart(64, "0");
        input += BigInt(roots[roots.length - 1]).toString(16).padStart(64, "0");

        for (let id of identity_commitment) {
            input += BigInt(id).toString(16).padStart(64, "0");
        }

        const hashed_inputs = ethers.utils.sha256(input);
        const bi_hashed_inputs = BigInt(hashed_inputs).toString(10);

        fullProof.publicSignals = [bi_hashed_inputs]
        const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf-8"))
        const res = await verifyProof(vKey, fullProof);
        expect(res).toBe(true)
    });
});


