use super::super::shutdown::Shutdown;
use super::frame;
use crate::comdata::{self, ExData};
use serde::{Deserialize, Serialize};

use super::connection::{APDUCodec, ClientConnetion};
use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use std::sync::Arc;
use tokio::{
    io::{self, BufWriter},
    net::{TcpListener, TcpStream},
    sync::{broadcast, mpsc, Semaphore},
    time::{self, Duration},
};
use tokio_util::codec::Framed;
/***************************************/
/* 服务器  用来接受 连接服务
可能工作在安全和非安全模式  */
/***************************************/

/*结合了管理和 单个连接配置  所以 就放一个结构     */
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct ConManagerCfg {
    //支持的最大连接数 默认100
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /*非安全接口  默认 8102     */
    #[serde(default = "default_no_secru_port")]
    pub no_secru_port: u32,
    /*是否启动 非安全接口*/
    #[serde(default = "default_no_secru_port_enable")]
    pub no_secru_port_enable: bool,
    /*安全接口  默认 9102     */
    #[serde(default = "default_secru_port")]
    pub secru_port: u32,
    /*是否同一个ip 只能一个链接   默认是  */
    #[serde(default = "default_same_ip_only_one_link")]
    pub same_ip_only_one_link: bool,
    /*test 测试报文间隔  默认60 秒 */
    #[serde(default = "default_ping_test_interval_sec")]
    pub ping_test_interval_sec: u32,
    /*证书文件路径     */
    #[serde(default = "default_cert_file_path")]
    pub cert_file_path: String,
    /*本地默认 apdu 长度      */
    #[serde(default = "default_apdu_len")]
    pub apdu_len: u16,
    #[serde(default = "default_asdu_len")]
    /*本地默认 asdu 长度     */
    pub asdu_len: usize,
}
fn default_max_connections() -> u32 {
    100
}
fn default_no_secru_port() -> u32 {
    8102
}
fn default_same_ip_only_one_link() -> bool {
    true
}

fn default_no_secru_port_enable() -> bool {
    true
}
fn default_secru_port() -> u32 {
    9102
}
fn default_ping_test_interval_sec() -> u32 {
    60
}
fn default_cert_file_path() -> String {
    "/zl/settings/mim.cer".to_string()
}
/*默认顶格了 ，然后支持分包发送     */
fn default_apdu_len() -> u16 {
    65535
}
fn default_asdu_len() -> usize {
    1024 * 1024 * 6
}

/// Server listener state. Created in the `run` call. It includes a `run` method
/// which performs the TCP listening and initialization of per-connection state.
#[derive(Debug)]
struct ConManager {
    pub cfg: Box<comdata::CfgData>,
    to_gui_info_rx: mpsc::Receiver<ExData>,
    to_main_info_tx: mpsc::Sender<ExData>,
    /// TCP listener supplied by the `run` caller.
    listener: TcpListener,

    limit_connections: Arc<Semaphore>,

    notify_shutdown: broadcast::Sender<()>,

    shutdown_complete_rx: mpsc::Receiver<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
    to_each_handle_pubch_gui: broadcast::Sender<ExData>,
}

pub async fn run(
    secur_mod:bool,/*加密模式     */
    cfg: &comdata::CfgData,
    listener: TcpListener,
    mut shutdown: broadcast::Receiver<()>,
    to_gui_info_rx: mpsc::Receiver<ExData>,
    to_main_info_tx: mpsc::Sender<ExData>,
    gui_complete_tx: mpsc::Sender<()>,
    to_each_handle_pubch_gui: broadcast::Sender<ExData>,
) -> crate::Result<()> {
    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

    let mut server =Box::new( ConManager {
        cfg:  Box::new(cfg.clone()) ,
        to_gui_info_rx,
        to_main_info_tx,
        listener,
        limit_connections: Arc::new(Semaphore::new(cfg.con_mgr_cfg.max_connections as usize)),
        notify_shutdown,
        shutdown_complete_tx,
        shutdown_complete_rx,
        to_each_handle_pubch_gui,
    });
    drop(cfg);

    tokio::select! {
        res = server.run() => {

            if let Err(err) = res {
                println!( "failed to accept,cause = {} ",err);
            }
        }

        _ = shutdown.recv() => {
            // The shutdown signal has been received.
            println!("gui get shutting down cmd");
            //shutting down
        }
    }

    let ConManager {
        mut shutdown_complete_rx,
        shutdown_complete_tx,
        notify_shutdown,
        ..
    } = *server;
    // When `notify_shutdown` is dropped, all tasks which have `subscribe`d will
    // receive the shutdown signal and can exit
    drop(notify_shutdown);
    // Drop final `Sender` so the `Receiver` below can complete
    drop(shutdown_complete_tx);

    // Wait for all active connections to finish processing. As the `Sender`
    // handle held by the listener has been dropped above, the only remaining
    // `Sender` instances are held by connection ClientConnetion tasks. When those drop,
    // the `mpsc` channel will close and `recv()` will return `None`.
    let _ = shutdown_complete_rx.recv().await;

    //告诉主函数 ，gui 退出了
    drop(gui_complete_tx);
    println!("all hands exit,gui exit now");

    Ok(())
}

impl ConManager {
    async fn run(&mut self) -> crate::Result<()> {
        println!("gui accepting inbound connections");

        loop {
            self.limit_connections.acquire().await.unwrap().forget();

            let socket = self.accept().await?;
            println!("get a client ");

            // Create the necessary per-connection ClientConnetion state.
            let mut client_connetion = Box::new(ClientConnetion {
                cfg: *self.cfg.clone(),
                // Get a handle to the shared database. Internally, this is an
                // `Arc`, so a clone only increments the ref count.
                to_main_info_tx: self.to_main_info_tx.clone(),
                // Initialize the connection state. This allocates read/write
                // buffers to perform redis protocol frame parsing.
                // connection: Framed<BufWriter<TcpStream>, APDUCodec>,
                connection: Framed::new(BufWriter::with_capacity(65535, socket), APDUCodec::new()),

                // connection:  Framed::new(BufWriter::new(socket), LengthDelimitedCodec::new()),

                // The connection state needs a handle to the max connections
                // semaphore. When the ClientConnetion is done processing the
                // connection, a permit is added back to the semaphore.
                limit_connections: self.limit_connections.clone(),

                // Receive shutdown notifications.
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),

                // Notifies the receiver half once all clones are
                // dropped.
                _shutdown_complete: self.shutdown_complete_tx.clone(),

                to_each_handle_rcvch: self.to_each_handle_pubch_gui.subscribe(),
            });
            // println!("get a client 002");

            tokio::spawn(async move {
                // println!("get a client,start a handle ");
                // Process the connection. If an error is encountered, log it.
                if let Err(err) = client_connetion.run().await {
                    println!("connection error cause = {} ", err);
                }
            });
            //println!("get a client 003");
        }
    }

    async fn accept(&mut self) -> crate::Result<TcpStream> {
        let mut backoff = 1;

        // Try to accept a few times
        loop {
            // Perform the accept operation. If a socket is successfully
            // accepted, return it. Otherwise, save the error.
            match self.listener.accept().await {
                Ok((socket, _)) => return Ok(socket),
                Err(err) => {
                    if backoff > 64 {
                        // Accept has failed too many times. Return the error.
                        return Err(err.into());
                    }
                }
            }

            // Pause execution until the back off period elapses.
            time::sleep(Duration::from_secs(backoff)).await;

            // Double the back off
            backoff *= 2;
        }
    }
}
