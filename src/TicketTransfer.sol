// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.10;

/// @title Ticket Transfer
/// @author kulkarohan
/// @notice A (useless) contract for testing EIP-712 signatures using Foundry
contract TicketTransfer {
    ///                                                          ///
    ///                       DOMAIN SEPARATOR                   ///
    ///                                                          ///

    /// @notice The EIP-712 domain separator
    bytes32 public immutable EIP_712_DOMAIN_SEPARATOR =
        keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TicketTransfer")),
                keccak256(bytes("1")),
                _chainId(),
                address(this)
            )
        );

    /// @notice The EIP-155 chain id
    function _chainId() private view returns (uint256 id) {
        assembly {
            id := chainid()
        }
    }

    ///                                                          ///
    ///                         TICKET DATA                      ///
    ///                                                          ///

    /// @notice The EIP-712 typehash for a signed ticket
    /// @dev keccak256("SignedTicket(uint256 id,uint256 expiry)");
    bytes32 public constant SIGNED_TICKET_TYPEHASH = 0x787f061deb861898126b36ccffa91598e7cdfe9951957c10f40a593d381075ce;

    /// @notice The metadata of a ticket
    /// @param seller The seller address
    /// @param id The ticket id
    /// @param expiry The ticket expiration time
    struct Ticket {
        address seller;
        uint256 id;
        uint256 expiry;
    }

    /// @notice If a given ticket has been transferred
    /// @dev Ticket id => Transferred
    mapping(uint256 => bool) public isTransferred;

    ///                                                          ///
    ///                       SIGNER RECOVERY                    ///
    ///                                                          ///

    /// @notice Recovers the signer of a given ticket
    /// @param _ticket The signed ticket
    /// @param _v The 129th byte and chain id of the signature
    /// @param _r The first 64 bytes of the signature
    /// @param _s Bytes 64-128 of the signature
    function _recoverSigner(
        Ticket calldata _ticket,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) private view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", EIP_712_DOMAIN_SEPARATOR, keccak256(abi.encode(SIGNED_TICKET_TYPEHASH, _ticket.id, _ticket.expiry)))
        );

        return ecrecover(digest, _v, _r, _s);
    }

    ///                                                          ///
    ///                        TICKET TRANSFER                   ///
    ///                                                          ///

    /// @notice Emitted upon a successful transfer
    /// @param id The ticket id
    /// @param seller The seller address
    /// @param buyer The buyer address
    event Transfer(uint256 id, address seller, address buyer);

    /// @notice Transfers a given signed ticket
    /// @param _ticket The signed ticket to transfer
    /// @param _v The 129th byte and chain id of the signature
    /// @param _r The first 64 bytes of the signature
    /// @param _s Bytes 64-128 of the signature
    function transfer(
        Ticket calldata _ticket,
        uint8 _v,
        bytes32 _r,
        bytes32 _s
    ) external {
        // Ensure the ticket has not expired
        require(_ticket.expiry == 0 || _ticket.expiry >= block.timestamp, "EXPIRED_TICKET");

        // Ensure the ticket has not been previously transferred
        require(!isTransferred[_ticket.id], "INVALID_TRANSFER");

        // Recover the ticket signer
        address recoveredSigner = _recoverSigner(_ticket, _v, _r, _s);

        // Ensure the recovered signer matches the ticket seller
        require(recoveredSigner == _ticket.seller, "INVALID_SIG");

        // Mark the ticket as transferred
        isTransferred[_ticket.id] = true;

        emit Transfer(_ticket.id, _ticket.seller, msg.sender);
    }
}