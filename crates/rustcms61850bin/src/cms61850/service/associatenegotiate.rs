/***************************************/
/*协商参数大小     */
/***************************************/
// AssociateNegotiateRequestPDU ::= SEQUENCE {
//     apduSize       [0] IMPLICIT INT16U,
//     asduSize       [1] IMPLICIT INT32U,
//     protocolVersion [2] IMPLICIT INT32U
// }
pub struct AssociateNegotiateRequestPDU {
    pub apdusize: u16,
    pub asdusize: u32,
    pub protocolversion: u32,
}

// AssociateNegotiate-ResponsePDU ::= SEQUENCE {
//     apduSize       [0] IMPLICIT INT16U,
//     asduSize       [1] IMPLICIT INT32U,
//     protocolVersion [2] IMPLICIT INT32U,
//     modelVersion   [3] IMPLICIT VisibleString
// }

pub struct AssociateNegotiateResponsePDU {
    pub apdusize: u16,
    pub asdusize: u32,
    pub protocolversion: u32,
    pub modelversion: String,
}
