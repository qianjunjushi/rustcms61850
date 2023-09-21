use super::super::shutdown::Shutdown;
use super::frame;
use crate::comdata::{self, CfgData, ExData};
use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{
    io::{self, BufWriter},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, Semaphore},
    time::{self, Duration},
};
use tokio_util::codec::{Decoder, Encoder, Framed};
/***************************************/
/*胖连接  里面有实际链接，也有状态机相关     */
/***************************************/

/***************************************/
/*通信配置     */
/***************************************/
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct ConCfg {
    /*test 测试报文间隔  默认60 秒 */
    #[serde(default = "default_ping_test_interval_sec")]
    pub ping_test_interval_sec: u32,
    /*当没有心跳的时候 关掉连接  默认2次     */
    #[serde(default = "default_close_count_when_no_ping_pong")]
    pub close_count_when_no_ping_pong: u32,
}
fn default_ping_test_interval_sec() -> u32 {
    60
}
fn default_close_count_when_no_ping_pong() -> u32 {
    2
}
#[derive(Default, Clone, Debug)]
pub struct RunningData {
    /*协商过后的apdu 长度 和asdu 的长度
    本地初始配置 只能从本地配置获取     */
    pub neg_apdu_len: u16,
    pub neg_asdu_len: usize,
}

impl RunningData {
    fn neg_len(&mut self, coming_apdu_len: u16, coming_asdu_len: usize) {
        //我的只能比你大 你小了 我就迁就你
        if coming_apdu_len < self.neg_apdu_len {
            self.neg_apdu_len = coming_apdu_len;
            println!(
                "con neg len origin {} now {}",
                self.neg_apdu_len, coming_apdu_len
            );
        }
        if coming_asdu_len < self.neg_asdu_len {
            self.neg_asdu_len = coming_asdu_len;
            println!(
                "con neg len origin {} now {}",
                self.neg_asdu_len, coming_asdu_len
            );
        }
    }
    /*只有第一次初始化的时候才需要  后面使用协商过来的数据     */
    fn update_from_cfg(&mut self, cfg: &CfgData) {
        self.neg_apdu_len = cfg.con_mgr_cfg.apdu_len;
        self.neg_asdu_len = cfg.con_mgr_cfg.asdu_len;
    }
}

#[derive(Default, Clone, Debug)]
pub struct Con {
    pub cfg: comdata::CfgData,
}
impl Con {
    pub fn new() -> Self {
        Con {
            ..Default::default()
        }
    }
}
#[derive(Debug, Clone)]
enum DecodeState {
    Head,
    Data(frame::APCH),
}
#[derive(Debug, Clone)]
pub struct APDUCodec {
    state: DecodeState,
}

impl APDUCodec {
    pub fn new() -> Self {
        Self {
            state: DecodeState::Head,
        }
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<frame::APCH>> {
        /*一个字节 控制位
        一个字节 服务码
        2个字节长度     */
        while src.len() >= 4 {
            if src[0] & 0x0F != 0x01 {
                src.advance(1);
            } else {
                break;
            }
        }
        if src.len() < 4 {
            // Not enough data
            return Ok(None);
        }
        /*协议号 只能 是1  表示61850     */
        let pi = 0x01;
        /*0 没有错误 ，1 有错误     */
        let is_err = if src[0] & 1 << 5 != 0 { true } else { false };
        /*有后续报文     */

        let have_next_frame = if src[0] & 1 << 7 != 0 { true } else { false };

        /*请求是 0  ，响应是1     */

        let is_resp = if src[0] & 1 << 6 != 0 { true } else { false };
        src.advance(1);
        /*服务码     */
        let serv_code = src.get_u8();
        /*asdu 帧长度  低位在前   小端模式   */
        let asdu_len = src.get_u16_le();

        let res = frame::APCH {
            pi,
            /*0 没有错误 ，1 有错误     */
            is_err,
            /*有后续报文     */
            have_next_frame,
            /*请求是 0  ，响应是1     */
            is_resp,
            /*服务码     */
            serv_code,
            /*asdu 帧长度  低位在前   小端模式   */
            asdu_len,
        };

        src.reserve(asdu_len as usize + 4);
        if asdu_len < 2 {
            println!("error asdu len {}", asdu_len);
            src.clear();
            return Ok(None);
        }
        Ok(Some(res))
    }

    fn decode_data(&self, apch: frame::APCH, src: &mut BytesMut) -> Option<frame::APDU> {
        // At this point, the buffer has already had the required capacity
        // reserved. All there is to do is read.
        if src.len() < apch.asdu_len as usize {
            return None;
        }
        let req_id = src.get_u16_le();
        let asdu = frame::ASDU {
            req_id,
            pay_load: src.split_to(apch.asdu_len as usize - 2).freeze(),
        };
        let apdu = frame::APDU { apch, asdu };
        src.reserve(4);
        Some(apdu)
    }
}

impl Decoder for APDUCodec {
    type Item = frame::APDU;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<frame::APDU>> {
        let apch = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(apch) => {
                    self.state = DecodeState::Data(apch.clone());
                    apch.clone()
                }
                None => return Ok(None),
            },
            DecodeState::Data(ref apch) => apch.clone(),
        };

        match self.decode_data(apch, src) {
            Some(data) => {
                // Update the decode state
                self.state = DecodeState::Head;

                // Make sure the buffer has enough space to read the next head
                src.reserve(1024);

                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}

impl Encoder<frame::APDU> for APDUCodec {
    type Error = io::Error;

    fn encode(&mut self, apdu: frame::APDU, dst: &mut BytesMut) -> Result<(), io::Error> {
        dst.reserve(apdu.apch.asdu_len as usize + 8);
        dst.put_slice(apdu.apch.to_bytes().as_ref());
        dst.put_u16_le(apdu.asdu.req_id);
        dst.extend_from_slice(apdu.asdu.pay_load.as_ref());
        //println!("ffffffffffffffffff{}   {}  {}  {}",dst[13],dst[14],dst[15],dst[16]);

        Ok(())
    }
}

impl ClientConnetion {
    pub async fn run(&mut self) -> crate::Result<()> {
        // As long as the shutdown signal has not been received, try to read a
        // new request frame.
        // println!("hand 01");
        let mut run_data = Box::new(RunningData::default());
        run_data.update_from_cfg(&self.cfg);

        while !self.shutdown.is_shutdown() {
            // While reading a request frame, also listen for the shutdown
            // signal.
            tokio::select! {
                res = self.connection.next() =>{
                    if res.is_some() {
                        //todo
                        //处理过来的信息


                    }else{
                        return Ok(());
                    }

                }
                //收到主路信息
                maininfo= self.to_each_handle_rcvch.recv() =>{
                    // use super::cmd;
                    // println!("recve rtdata ");

                    match maininfo{
                        Ok(ExData::CfgData(box_cfg_data))=>{

                            /*收到发来的配置 更新自身     */
                            self.cfg=box_cfg_data;






                        }



                        _=>{
                                bail!("main pub closed ,should not happen " );
                        }

                    }



                }

                _ = self.shutdown.recv() => {

                    return Ok(());
                }
            };
        }

        Ok(())
    }
}

impl Drop for ClientConnetion {
    fn drop(&mut self) {
        self.limit_connections.add_permits(1);
    }
}

/// Per-connection ClientConnetion. Reads requests from `connection` and applies the
/// commands to `db`.
#[derive(Debug)]
pub struct ClientConnetion {
    pub cfg: comdata::CfgData,
    pub to_main_info_tx: mpsc::Sender<ExData>,
    pub connection: Framed<BufWriter<TcpStream>, APDUCodec>,
    pub limit_connections: Arc<Semaphore>,
    pub shutdown: Shutdown,
    /// Not used directly. Instead, when `ClientConnetion` is dropped...?
    pub _shutdown_complete: mpsc::Sender<()>,
    pub to_each_handle_rcvch: broadcast::Receiver<ExData>,
}
