// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

import {DSTest} from "ds-test/test.sol";

import {TicketTransfer} from "../TicketTransfer.sol";
import {VM} from "./VM.sol";

/// @title Ticket Transfer Test
/// @author kulkarohan
/// @notice Unit tests for Ticket Transfer
contract TicketTransferTest is DSTest {
    ///                                                          ///
    ///                            SETUP                         ///
    ///                                                          ///

    // Used to access the `addr` and `sign` cheatcodes (see https://book.getfoundry.sh/cheatcodes/index.html)
    VM internal vm;

    // Used to store a `TicketTransfer` instance
    TicketTransfer internal ticketTransfer;

    // Store the private key for a mock seller
    uint256 internal sellerPrivateKey = 0xB0B;

    // Used to store the mock seller address
    address internal seller;

    function setUp() public {
        // Access cheatcodes
        vm = VM(HEVM_ADDRESS);

        // Derive the seller address using the `addr` cheatcode
        seller = vm.addr(sellerPrivateKey);

        // Deploy `TicketTransfer`
        ticketTransfer = new TicketTransfer();
    }

    ///                                                          ///
    ///                            UTILS                         ///
    ///                                                          ///

    /// @notice Utility function to sign a ticket
    /// @param _privateKey The private key of the signer
    /// @param _ticketId The ticket id to sign
    /// @param _ticketExpiry The ticket expiration to sign
    /// @return ticket The signed ticket object
    /// @return v r s The generated signature
    function signTicket(
        uint256 _privateKey,
        uint256 _ticketId,
        uint256 _ticketExpiry
    )
        public
        returns (
            TicketTransfer.Ticket memory ticket,
            uint8 v,
            bytes32 r,
            bytes32 s
        )
    {
        // The domain separator from the `TicketTransfer` contract
        // Note: update the chain id and verifying contract accordingly
        bytes32 EIP_712_DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TicketTransfer")),
                keccak256(bytes("1")),
                99, // Forge chain id
                address(ticketTransfer) // Change from `address(this)`
            )
        );

        // The signed ticket typehash from the `TicketTransfer` contract
        // keccak256("SignedTicket(uint256 id,uint256 expiry)");
        bytes32 SIGNED_TICKET_TYPEHASH = 0x787f061deb861898126b36ccffa91598e7cdfe9951957c10f40a593d381075ce;

        // Create a ticket with the mock seller and given arguments
        ticket = TicketTransfer.Ticket({seller: seller, id: _ticketId, expiry: _ticketExpiry});

        // Use the `sign` cheatcode to sign the ticket with the given private key
        (v, r, s) = vm.sign(
            _privateKey,
            keccak256(abi.encodePacked("\x19\x01", EIP_712_DOMAIN_SEPARATOR, keccak256(abi.encode(SIGNED_TICKET_TYPEHASH, _ticketId, _ticketExpiry))))
        );
    }

    ///                                                          ///
    ///                             TEST                         ///
    ///                                                          ///

    function test_TransferTicket() public {
        // Create ticket data
        uint256 ticketId = 1;
        uint256 ticketExpiry = 0;

        // Get a ticket signed by the seller and the associated signature
        (TicketTransfer.Ticket memory ticket, uint8 v, bytes32 r, bytes32 s) = signTicket(sellerPrivateKey, ticketId, ticketExpiry);

        // Call `transfer()` with the ticket and seller signature
        ticketTransfer.transfer(ticket, v, r, s);

        // Ensure the ticket is marked as transferred
        require(ticketTransfer.isTransferred(1));
    }

    function testRevert_ExpiredTicket() public {
        // Create ticket data
        uint256 ticketId = 1;
        uint256 ticketExpiry = 23 hours;

        // Get a ticket signed by the seller and the associated signature
        (TicketTransfer.Ticket memory ticket, uint8 v, bytes32 r, bytes32 s) = signTicket(sellerPrivateKey, ticketId, ticketExpiry);

        // Fast forward the block timestamp one hour past ticket expiration
        vm.warp(1 days);

        // Expect the call to revert, as the ticket has expired
        vm.expectRevert("EXPIRED_TICKET");
        ticketTransfer.transfer(ticket, v, r, s);
    }

    function testRevert_InvalidTransfer() public {
        // Create ticket data
        uint256 ticketId = 1;
        uint256 ticketExpiry = 0;

        // Get a ticket signed by the seller and the associated signature
        (TicketTransfer.Ticket memory ticket, uint8 v, bytes32 r, bytes32 s) = signTicket(sellerPrivateKey, ticketId, ticketExpiry);

        // Call `transfer()` with the ticket and seller signature
        ticketTransfer.transfer(ticket, v, r, s);

        // Expect a subsequent call to revert, as the ticket has already been transferred
        vm.expectRevert("INVALID_TRANSFER");
        ticketTransfer.transfer(ticket, v, r, s);
    }

    function testRevert_InvalidSig() public {
        // Create ticket data
        uint256 ticketId = 1;
        uint256 ticketExpiry = 0;

         // Get a ticket signed by a user other than the mock seller
        (TicketTransfer.Ticket memory ticket, uint8 v, bytes32 r, bytes32 s) = signTicket(0xA11CE, ticketId, ticketExpiry);

        // Expect the call to revert, as the given signature is not from the mock seller
        vm.expectRevert("INVALID_SIG");
        ticketTransfer.transfer(ticket, v, r, s);
    }
}
