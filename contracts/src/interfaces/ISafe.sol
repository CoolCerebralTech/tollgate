// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISafe {
    function setGuard(address guard) external;
    function getGuard() external view returns (address);
}