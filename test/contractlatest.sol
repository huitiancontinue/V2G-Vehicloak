pragma solidity ^0.4.24;

contract Sample {

    struct EV {
        bytes32 cmts_A;
        bytes32 cmts_B;
	bytes32 cmtc;
	address addressa;
        uint N;
	uint D;
        bytes32 H0;
    }

    mapping(address => EV) public ev;

    constructor() public {

    }

    function Commit(bytes32 h0,bytes32 cmtc,uint n) public {
            ev[msg.sender].addressa = msg.sender;
            ev[msg.sender].cmtc = cmtc;
            ev[msg.sender].N = n;
            ev[msg.sender].H0 = h0;

    }

    function Claim(bytes32 hi,uint L,bytes32 cmts_b,address addressa) public {
            uint temp;
            bytes32 myhash = hi;
            for(uint i = 0;i<200;i++){
		if(myhash == ev[addressa].H0){
                    temp = i;
                    break;
                }
                myhash = keccak256(abi.encodePacked(myhash));
            }
         
            if(temp == L){
		ev[addressa].D = ev[addressa].N - L;
                ev[addressa].cmts_B = cmts_b;
            }
    }


    function Refund(uint D,bytes32 cmts_a) public {
            if(ev[msg.sender].D == D){
                ev[msg.sender].cmts_A = cmts_a;  
            }
    }
}
