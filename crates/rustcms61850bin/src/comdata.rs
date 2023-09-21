pub use crate::cms61850::net::cmscon::connection;
pub use crate::cms61850::net::cmscon::connection_manager;
use tokio::fs;
use anyhow::{bail,Context};
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct WdCfg {
    #[serde(default = "default_close_watchdog")]
    pub close_watchdog: bool, /*是否关闭看门狗     */
    #[serde(default = "default_wd_filename")]
    pub wd_filename: String,
    /*当所有链接断开后是否重启     */
    #[serde(default = "default_reboot_when_no_con")]
    pub reboot_when_no_con: bool,
    /*当所有链接断开后多久重启     */
    #[serde(default = "default_reboot_when_no_con_sec")]
    pub reboot_when_no_con_sec: u32,
}
fn default_close_watchdog() -> bool {
    false
}
fn default_wd_filename() -> String {
    String::from("/dev/wd")
}
fn default_reboot_when_no_con() -> bool {
    true
}
fn default_reboot_when_no_con_sec() -> u32 {
    300
}

/***************************************/
/*这次准备 各个配置 分区域划分功能     */
/***************************************/
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct CfgData {
    //连接配置
    pub con_cfg: connection::ConCfg,
    /* 服务配置     */
    pub con_mgr_cfg: connection_manager::ConManagerCfg,
    /*看门狗配置     */
    pub wd_cfg: WdCfg,
}

impl CfgData {
    pub async fn read_startup_cfg_file(cfg_file_name: impl AsRef<Path>) -> crate::Result<Self> {
        let content = fs::read_to_string(cfg_file_name).await?;
    
        let res: CfgData = serde_json::from_str(&content).context("parse comdata cfg errr")?;
        Ok(res)
    }
    
}

#[derive(Clone, Debug)]
pub enum ExData {
    CfgData(CfgData),
}
