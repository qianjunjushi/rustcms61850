use crate::comdata;
/***************************************/
/*真正的 汇总中心     */
/***************************************/

pub struct CmsUnit {
    //初始配置
    pub cfg_data: comdata::CfgData,
}
impl CmsUnit {
    /*运行函数     */
    pub async fn run(&mut self) {}
    /*构造函数     */
    pub fn new(cfg:&comdata::CfgData) -> CmsUnit {
        CmsUnit {
            cfg_data: cfg.clone(),
        }
    }
}
