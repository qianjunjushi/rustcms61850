#![allow(dead_code)]
#![allow(unused_imports)]
mod cfg;
mod comdata;
mod glb;
use cfg::scl2;
mod cms61850;
mod ctrlcshutdown;
mod utils;
mod watchdog;
pub use anyhow::Result;
use chrono;
use cms61850::net::cmscon::connection_manager;
use tokio::{
    net::TcpListener,
    signal,
    sync::{broadcast, mpsc},
    time,
};

/***************************************/
/***********   常量区域      Start ******************/
/***************************************/
//主版本号
const MAIN_VERION: u32 = 0;
//次版本号
const SUB_VERION: u32 = 1;
//修改序号
const CHANGE_INDEX: u32 = 2;
//修改时间
const CHANGE_DATE: u32 = 230906;

/*初始配置文件路径     */
const CFG_FILE_NAME: &str = "cms61850.json";

const CHANELENUM: usize = 128;
/***************************************/
/***********   常量区域      End ******************/
/***************************************/

#[tokio::main]
pub async fn main() -> Result<()> {
    println!(
        "Rust Cms 61850 ,version :{}.{}.{}_{}",
        MAIN_VERION, SUB_VERION, CHANGE_INDEX, CHANGE_DATE
    );
    println!("©20232 XRWH.Tec. All rights reserved.");
    println!("AUTHOR Chen  ,2023.09.06");
    println!(
        "RUN START SINCE {}",
        chrono::Utc::now()
            .checked_add_signed(chrono::Duration::seconds(8 * 3600))
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    );
    let startup_cfg = cfg::startupcfg::read_startup_cfg_file("startupcfg.json").await?;
    println!("startup cfg {:?}", startup_cfg);
    let scl_info = scl2::scl_parse(
        &startup_cfg.scl_filename,
        &startup_cfg.ied_name,
        &startup_cfg.access_point_name,
    )
    .await?;
    tokio::fs::write("outputinfo.json", format!("{:?}", scl_info).as_bytes()).await?;
    //println!("scl info {:?}", scl_info);

    /***************************************/
    /***********   处理ctrl C 信号      Start ******************/
    /***************************************/
    //用来通知 子线程推出的广告
    let (notify_shutdown, _) = broadcast::channel(1);
    //上面的用来给  ctrl-c 控制 这个 用来给各个子线程使用
    let notify_shutdown_origin = notify_shutdown.clone();
    //用来等待所有 子模块退出
    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    /*启动 ctrl-C 捕获程序*/
    let cltrctask = tokio::spawn(async move {
        // Process the connection. If an error is encountered, log it.
        if let Err(err) = ctrlcshutdown::slow_shutdown(notify_shutdown, signal::ctrl_c()).await {
            println!("err{}", err);
        }
        println!("Get ctrl-C cmd ");
    });
    /***************************************/
    /***********   处理ctrl C 信号        End ******************/
    /***************************************/

    /***************************************/
    /***********   消息中枢      Start ******************/
    /***************************************/
    //用来群发订阅消息的
    let (to_each_handle_pubch, _) = broadcast::channel(6);
    let (to_main_info_tx, mut to_main_info_rx) = mpsc::channel(CHANELENUM);

    /***************************************/
    /***********  消息中枢        End ******************/
    /***************************************/

    let local_cfg = comdata::CfgData::read_startup_cfg_file(CFG_FILE_NAME).await?;
    println!("local cfg {:?}", local_cfg);

    /***************************************/
    /***********   启动安全 和非安全端口      Start ******************/
    /***************************************/
    if local_cfg.con_mgr_cfg.no_secru_port_enable {
        let addr = format!("0.0.0.0:{}", local_cfg.con_mgr_cfg.no_secru_port);
        let listener = TcpListener::bind(&addr).await?;
        let (to_no_secru_info_tx, to_no_secru_info_rx) = mpsc::channel(CHANELENUM);

        let no_secru_complete_tx = (&shutdown_complete_tx).clone();
        let no_secru_shutdown = (&notify_shutdown_origin).subscribe();
        let to_each_handle_pubch_no_secru = to_each_handle_pubch.clone();
        //let to_each_handle_pubch_6_or_485 = to_each_handle_pubch.subscribe();
        //println!("d60bin 006.1");
        let to_main_info_tx_no_secru = to_main_info_tx.clone();
        let cfg = Box::new(local_cfg.clone());
        tokio::spawn(async move {
            time::sleep(std::time::Duration::from_secs(1)).await;
            // Process the connection. If an error is encountered, log it.

            if let Err(err) = connection_manager::run(
                false,
                &cfg,
                listener,
                no_secru_shutdown,
                to_no_secru_info_rx,
                to_main_info_tx_no_secru,
                no_secru_complete_tx,
                to_each_handle_pubch_no_secru,
            )
            .await
            {
                // println!("d60bin 007");
                println!("err{}", err);
            }
        });
    }

    let addr = format!("0.0.0.0:{}", local_cfg.con_mgr_cfg.secru_port);
    let listener = TcpListener::bind(&addr).await?;
    let (to_secru_info_tx, to_secru_info_rx) = mpsc::channel(CHANELENUM);

    let secru_complete_tx = (&shutdown_complete_tx).clone();
    let secru_shutdown = (&notify_shutdown_origin).subscribe();
    let to_each_handle_pubch_secru = to_each_handle_pubch.clone();
    //let to_each_handle_pubch_6_or_485 = to_each_handle_pubch.subscribe();
    //println!("d60bin 006.1");
    let cfg = Box::new(local_cfg.clone());
    let to_main_info_tx_secru = to_main_info_tx.clone();
    tokio::spawn(async move {
        time::sleep(std::time::Duration::from_secs(1)).await;
        // Process the connection. If an error is encountered, log it.

        if let Err(err) = connection_manager::run(
             true,
            &cfg,
            listener,
            secru_shutdown,
            to_secru_info_rx,
            to_main_info_tx_secru,
            secru_complete_tx,
            to_each_handle_pubch_secru,
        )
        .await
        {
            println!(" secru err{}", err);
        }
    });

    /***************************************/
    /***********  启动安全 和非安全端口       End ******************/
    /***************************************/

    Ok(())
}
