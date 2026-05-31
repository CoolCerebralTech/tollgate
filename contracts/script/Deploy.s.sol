// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {TollgateGuard} from "../src/TollgateGuard.sol";

/**
 * @title  Deploy
 * @notice Deploys TollgateGuard to the target network.
 *
 * Usage — local Anvil:
 *   forge script script/Deploy.s.sol \
 *     --rpc-url http://127.0.0.1:8545 \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast
 *
 * Usage — Base Sepolia:
 *   forge script script/Deploy.s.sol \
 *     --rpc-url base_testnet \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast --verify \
 *     --etherscan-api-key $BASESCAN_API_KEY
 */
contract Deploy is Script {
    function run() external {
        // Load notary address — required.
        address notaryAddress = vm.envAddress("TOLLGATE_NOTARY_ADDRESS");
        require(notaryAddress != address(0), "Deploy: TOLLGATE_NOTARY_ADDRESS not set");

        // Safe address — for local Anvil testing we use the deployer as the Safe.
        // In production this must be a real Gnosis Safe address.
        address safeAddress = vm.envOr("SAFE_ADDRESS", address(0));
        if (safeAddress == address(0)) {
            // Default to deployer address for local testing.
            safeAddress = msg.sender;
        }

        console.log("=== TOLLGATE GUARD DEPLOYMENT ===");
        console.log("Chain ID      :", block.chainid);
        console.log("Notary        :", notaryAddress);
        console.log("Safe          :", safeAddress);
        console.log("Deployer      :", msg.sender);

        vm.startBroadcast();
        TollgateGuard guard = new TollgateGuard(notaryAddress, safeAddress);
        vm.stopBroadcast();

        console.log("=================================");
        console.log("Guard deployed:", address(guard));
        console.log("Domain sep    :");
        console.logBytes32(guard.getDomainSeparator());
        console.log("Type hash     :");
        console.logBytes32(guard.getApprovalTokenTypeHash());
        console.log("=================================");
        console.log("Add to .env -> GUARD_ADDRESS=", address(guard));
        console.log("Add to Phase 1 .env -> GUARD_CONTRACT_ADDRESS=", address(guard));
    }
}
