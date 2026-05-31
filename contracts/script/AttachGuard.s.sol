// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {ISafe} from "../src/interfaces/ISafe.sol";
import {TollgateGuard} from "../src/TollgateGuard.sol";

/**
 * @title  AttachGuard
 * @notice Attaches a deployed TollgateGuard to a Gnosis Safe.
 *
 * Usage:
 *   forge script script/AttachGuard.s.sol \
 *     --rpc-url http://127.0.0.1:8545 \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast
 */
contract AttachGuard is Script {
    function run() external {
        address guardAddress = vm.envAddress("GUARD_ADDRESS");
        address safeAddress  = vm.envAddress("SAFE_ADDRESS");

        require(guardAddress != address(0), "AttachGuard: GUARD_ADDRESS not set");
        require(safeAddress  != address(0), "AttachGuard: SAFE_ADDRESS not set");

        console.log("=== ATTACHING GUARD TO SAFE ===");
        console.log("Safe address  :", safeAddress);
        console.log("Guard address :", guardAddress);

        ISafe safe = ISafe(safeAddress);

        vm.startBroadcast();
        safe.setGuard(guardAddress);
        vm.stopBroadcast();

        // Verify attachment succeeded.
        address attached = safe.getGuard();
        require(attached == guardAddress, "AttachGuard: verification failed");

        console.log("Guard attached successfully");
        console.log("Verified getGuard() =", attached);
    }
}
