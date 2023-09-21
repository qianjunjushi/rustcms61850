use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::{path::Path, rc};
use tokio::fs;
use crate::comdata;
//todo
/*可能需要的配置
是否关闭 8102端口
是否同一个ip 只能一个链接
最大链接数





*/
/***************************************/
/***********   功能记录      Start ******************/
/***************************************/
    /*1 test 报文 确定对面是否还活着 周期1-5分钟     */
    /*2 stream 要设置 keepalive 参数     */
    
/***************************************/
/***********  功能记录        End ******************/
/***************************************/

// 用来读取配置的文件相关

#[derive(Serialize, Deserialize, Debug)]
pub struct StartupCfg {
    pub scl_filename: String,
    pub ied_name: String,
    pub access_point_name: String,
    pub report_scan_rate: u32, /* Report scan rate in milliseconds	*/
    pub brcbbuffersize: u32,   /* Buffered report buffer size.		*/
    pub logscanratems: u32,    /* Log scan rate in milliseconds	*/
    pub logmaxentries: u32,    /* Maximim number of entries in Log	*/
    
    

}


pub async fn read_startup_cfg_file(cfg_file_name: impl AsRef<Path>) -> crate::Result<StartupCfg> {
    let content = fs::read_to_string(cfg_file_name).await?;

    let res: StartupCfg = serde_json::from_str(&content).context("parse startup cfg errr")?;
    Ok(res)
}
