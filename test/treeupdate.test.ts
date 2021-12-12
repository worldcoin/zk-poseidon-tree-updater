const { generateMerkleProof } = require("@libsem/protocols");
const { ZkIdentity } = require("@libsem/identity");

import { MerkleProof } from "@libsem/types"
import { genProof, verifyProof } from "../src";
import * as fs from "fs";
import * as path from "path";

const BATCH_SIZE = 2;
const ZERO_VALUE = BigInt(0)

describe('Proof test', () => {
    it("Should create proof", async () => {
        const commitments = []
        const premerkleProof: MerkleProof = generateMerkleProof(10, ZERO_VALUE, 5, [ZERO_VALUE], ZERO_VALUE)
        
        const identity_path_index = [];
        const path_elements = [];
        const identity_commitment = [];
        const roots = [premerkleProof.root];

        for (let i = 0; i < BATCH_SIZE; i++) {
            const identity = new ZkIdentity();
            const id_comm = identity.genIdentityCommitment();
    
            commitments.push(id_comm)
            const postmerkleProof: MerkleProof = generateMerkleProof(10, ZERO_VALUE, 5, commitments, id_comm)
    
            identity_path_index.push(postmerkleProof.indices)
            path_elements.push(postmerkleProof.pathElements)
            identity_commitment.push(id_comm)
            roots.push(postmerkleProof.root)
        }

        const grothInput = {
            identity_path_index,
            path_elements,
            roots,
            identity_commitment
        };

        const wasmFilePath: string = path.join("./zkFiles", "circuit.wasm")
        const finalZkeyPath: string = path.join("./zkFiles", "circuit_final.zkey")
        const vkeyPath = path.join("./zkFiles", "verification_key.json")

        const fullProof = await genProof(grothInput, wasmFilePath, finalZkeyPath);
        fullProof.publicSignals = [roots[0], roots[roots.length - 1], ...identity_commitment]
        const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf-8"))
        const res = await verifyProof(vKey, fullProof);
        expect(res).toBe(true)
    });
});


