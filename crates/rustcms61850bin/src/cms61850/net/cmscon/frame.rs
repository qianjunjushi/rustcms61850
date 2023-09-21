use crate::utils;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/*关联服务     */
const ASSOCIATE: u8 = 1;
pub const ABORT: u8 = 2;
pub const RELEASE: u8 = 3;
/*模型和数据服务     */
pub const GETSERVERDIRECTORY: u8 = 80;
pub const GETLOGICDEVICEDIRECTORY: u8 = 81;
pub const GETLOGICNODEDIRECTORY: u8 = 82;
pub const GETALLDATAVALUES: u8 = 83;
pub const GETALLDATADEFINITION: u8 = 155;
pub const GETALLCBVALUES: u8 = 156;
pub const GETDATAVALUES: u8 = 48;
pub const SETDATAVALUES: u8 = 49;
pub const GETDATADIRECTORY: u8 = 50;
pub const GETDATADEFINITION: u8 = 51;
/*数据集服务     */
pub const CREATEDATASET: u8 = 54;
pub const DELETEDATASET: u8 = 55;
pub const GETDATASETDIRECTORY: u8 = 57;
pub const GETDATASETVALUES: u8 = 58;
pub const SETDATASETVALUES: u8 = 59;
/*控制服务     */
pub const SELECT: u8 = 68;
pub const SELECTWITHVALUE: u8 = 69;
pub const CANCEL: u8 = 70;
pub const OPERATE: u8 = 71;
pub const COMMANDTERMINATION: u8 = 72;
pub const TIMEACTIVATEDOPERATE: u8 = 73;
pub const TIMEACTIVATEDOPERATETERMINATION: u8 = 74;

/*定值组服务     */
pub const SELECTACTIVESG: u8 = 84;
pub const SELECTEDITSG: u8 = 85;
pub const SETEDITSGVALUE: u8 = 86;
pub const CONFIRMEDITSGVALUES: u8 = 87;
pub const GETEDITSGVALUE: u8 = 88;
pub const GETSGCBVALUES: u8 = 89;

/*报告服务     */
pub const REPORT: u8 = 90;
pub const GETBRCBVALUES: u8 = 91;
pub const SETBRCBVALUES: u8 = 92;
pub const GETURCBVALUES: u8 = 93;
pub const SETURCBVALUES: u8 = 94;

/*日志服务     */
pub const GETLCBVALUES: u8 = 95;
pub const SETLCBVALUES: u8 = 96;
pub const QUERYLOGBYTIME: u8 = 97;
pub const QUERYLOGAFTER: u8 = 98;
pub const GETLOGSTATUSVALUES: u8 = 99;
/*GOOSE 控制     */
pub const GETGOCBVALUES: u8 = 102;
pub const SETGOCBVALUES: u8 = 103;
/*smv 控制块     */
pub const GETMSVCBVALUES: u8 = 105;
pub const SETMSVCBVALUES: u8 = 106;
/*文件服务     */
pub const GETFILE: u8 = 128;
pub const SETFILE: u8 = 129;
pub const DELETEFILE: u8 = 130;
pub const GETFILEATTRIBUTEVALUES: u8 = 131;
pub const GETFILEDIRECTORY: u8 = 132;

/*远程过程调用     */
pub const GETRPCINTERFACEDIRECTORY: u8 = 110;
pub const GETRPCMETHODDIRECTORY: u8 = 111;
pub const GETRPCINTERFACEDEFINITION: u8 = 112;
pub const GETRPCMETHODDEFINITION: u8 = 113;
pub const RPCCALL: u8 = 114;

pub const TEST: u8 = 153;
/*关联协商     */
pub const ASSOCIATENEGOTIATE: u8 = 154;

pub struct FrameCfg {}

#[derive(Default, Clone, Debug)]
pub struct APCH {
    /*协议号 只能 是1  表示61850     */
    pub pi: u8,
    /*0 没有错误 ，1 有错误     */
    pub is_err: bool,
    /*有后续报文     */
    pub have_next_frame: bool,
    /*请求是 0  ，响应是1     */
    pub is_resp: bool,
    /*服务码     */
    pub serv_code: u8,
    /*asdu 帧长度  低位在前   小端模式   */
    pub asdu_len: u16,
}
impl APCH {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(4);
        let mut first_b: u8 = 0;
        first_b |= 0x01;
        if self.is_err {
            utils::bstr_bit_set_on(&mut [first_b], 5);
        }
        if self.is_resp {
            utils::bstr_bit_set_on(&mut [first_b], 6);
        }
        if self.have_next_frame {
            utils::bstr_bit_set_on(&mut [first_b], 7);
        }
        buf.put_u8(first_b);
        buf.put_u8(self.serv_code);
        buf.put_u16_le(self.asdu_len);

        buf.freeze()
    }
    fn set_err(&mut self, err: bool) -> &mut Self {
        self.is_err = err;
        self
    }
    fn set_resp(&mut self, resp: bool) -> &mut Self {
        self.is_resp = resp;
        self
    }
    fn set_have_next_frame(&mut self, have_next_frame: bool) -> &mut Self {
        self.have_next_frame = have_next_frame;
        self
    }
    fn set_serv_code(&mut self, serv_code: u8) -> &mut Self {
        self.serv_code = serv_code;
        self
    }
    fn set_pi(&mut self) -> &mut Self {
        self.pi = 0x01;
        self
    }
    fn set_asdu_len(&mut self, asdu_len: u16) -> &mut Self {
        self.asdu_len = asdu_len;
        self
    }
}

#[derive(Default, Clone, Debug)]
pub struct ASDU {
    /*初始为0 ，后来 1-65535 翻转为1  ,
    0 是非请求报文 比如报告    */
    pub req_id: u16,
    /*内容载荷     */
    pub pay_load: Bytes,
}
impl ASDU {
    pub fn set_req_id(&mut self, req_id: u16) {
        self.req_id = req_id;
    }
    pub fn set_pay_load(&mut self, pay_load: Bytes) {
        self.pay_load = pay_load;
    }
}
#[derive(Default, Clone, Debug)]
pub struct APDU {
    pub apch: APCH,
    pub asdu: ASDU,
}
impl APDU {
    pub fn to_bytes(&self) -> Bytes{
        let mut buf =BytesMut::with_capacity(self.apch.asdu_len as usize + 6);
        buf.put_slice(self.apch.to_bytes().as_ref());
        buf.put_u16_le(self.asdu.req_id);   
        buf.put_slice(self.asdu.pay_load.as_ref());
        buf.freeze()
    }
}

impl APDUBuilder {
    pub fn pack(self, neg_apdu_len: u16, neg_asdu_len: usize) -> Vec<APDU> {
        let mut ret: Vec<APDU> = Vec::new();
        let mut apch = APCH::default();
        apch.set_pi()
            .set_err(self.is_err)
            .set_resp(self.is_resp)
            .set_serv_code(self.serv_code);
        let mut asdu = ASDU::default();
        asdu.set_req_id(self.req_id);
        asdu.pay_load = Bytes::new();
        let frame_support = if usize::from(neg_apdu_len) < neg_asdu_len {
            true
        } else {
            false
        };
        let need_frame = if self.total_pay_load.len() + 6 > neg_apdu_len as usize {
            true
        } else {
            false
        };
        if self.total_pay_load.len() + 2 > neg_asdu_len as usize || (need_frame && !frame_support) {
            let mut apdu = APDU::default();
            // apdu.apch.set
            apdu.apch.set_err(true); /*分包不能 长度超长 就发送错误消息吧     */
            apdu.apch.set_asdu_len(2); /* 2  for  reqid     */
            apdu.apch.set_have_next_frame(false);
            apdu.asdu = asdu;
            ret.push(apdu);
            return ret;
        }

        /*1、分包发送     */
        if need_frame {
            //分包发送
            let packet_piece_len = neg_apdu_len as usize - 6;
            let last_piece_len = self.total_pay_load.len() % packet_piece_len;
            let last_piece_len = if last_piece_len == 0 {
                packet_piece_len
            } else {
                last_piece_len
            };
            let packet_count =
                (self.total_pay_load.len() + packet_piece_len - 1) / packet_piece_len;
            for i in 0..packet_count {
                let mut apdu_ele = APDU::default();
                apdu_ele.apch = apch.clone();
                if i == packet_count - 1 {
                    apdu_ele.apch.set_have_next_frame(false);
                    apdu_ele.apch.set_asdu_len(2 + packet_piece_len as u16);
                    apdu_ele.asdu.pay_load = self
                        .total_pay_load
                        .slice(i * packet_piece_len as usize..(i + 1) * packet_piece_len as usize);
                } else {
                    apdu_ele.apch.set_have_next_frame(true);
                    apdu_ele.apch.set_asdu_len(2 + last_piece_len as u16);
                    apdu_ele.asdu.pay_load = self
                        .total_pay_load
                        .slice(i * packet_piece_len as usize..(i + 1) * packet_piece_len as usize);
                }
            }
            return ret;
        } else {
            let mut apdu_ele = APDU::default();
            apdu_ele.apch = apch.clone();
            apdu_ele.apch.set_have_next_frame(false);
            apdu_ele
                .apch
                .set_asdu_len(2 + self.total_pay_load.len() as u16);
            apdu_ele.asdu.pay_load = self.total_pay_load.clone();
            ret.push(apdu_ele);
            return ret;
        }
    }

     

      
     
}

pub struct APDUBuilder {
    /*0 没有错误 ，1 有错误     */
    pub is_err: bool,
    /*请求是 0  ，响应是1     */
    pub is_resp: bool,
    /*服务码     */
    pub serv_code: u8,

    pub req_id: u16,
    /*内容载荷     */
    pub total_pay_load: Bytes,
}
