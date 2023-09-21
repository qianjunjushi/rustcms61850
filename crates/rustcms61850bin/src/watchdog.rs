use crate::comdata;
use std::collections::HashMap;
use std::io;
use std::{time::Duration, u32};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, mpsc};
use tokio::time;

#[derive(Clone, Debug)]
pub enum FeedId {
    Ser1 = 0,
    Ser2 = 1,
    Ser3 = 2,
    Ser4 = 3,
    S232 = 4,
    Can1 = 5,
    Can2 = 6,
    Can3 = 7,
    Can4 = 8,
    GuiWork = 26,

    UNknow,
}
pub enum WdFrame {
    Feed(FeedId),
    Reg(FeedItem),
}

#[derive(Debug)]
pub struct FeedItem {
    /// Uniquely identifies this entry.
    pub feed_id: FeedId,
    pub name: String,
    pub feed_limit: u32,
    pub now_feed: u32,
}

#[derive(Debug)]
pub struct WatcdogOpr {
    /// Uniquely identifies this entry.
    feeditems: HashMap<u8, FeedItem>,
}

impl WatcdogOpr {
    // Create a new wathdog observer

    pub fn new() -> WatcdogOpr {
        WatcdogOpr {
            feeditems: HashMap::new(),
        }
    }

    pub fn reg_new_item(&mut self, feedid: FeedId, name: String, feed_limit: u32) {
        self.feeditems.insert(
            feedid as u8,
            FeedItem {
                feed_id: FeedId::UNknow,
                name,
                feed_limit,
                now_feed: 0,
            },
        );
    }
    pub fn reg_new_item_total(&mut self, item: FeedItem) {
        self.feeditems.insert(item.feed_id.clone() as u8, item);
    }
}

/*启动看门狗的入口总函数**/
pub async fn watch_dog_run(
    mut wdrec: mpsc::Receiver<WdFrame>,
    mut shutdown: broadcast::Receiver<()>,
    _shutdown_complete_tx_wd: mpsc::Sender<()>,
    mut to_each_handle_pubch_wd: broadcast::Receiver<comdata::ExData>,
) -> crate::Result<()> {
    let mut interval = time::interval(Duration::from_secs(3));
    let mut send_this_time;

    let mut feeidu8: u8;
    let mut wdopr = WatcdogOpr::new();
    let mut close_watchdog = false;
    if let Ok(mut wd) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/watchdog")
        .await
    {
        println!("open wathdog Ok");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    /*增加所有检测计数
                    后续会改为3秒一次
                    */
                    for val in wdopr.feeditems.values_mut() {
                        if  val.now_feed < 9999 {
                            val.now_feed = val.now_feed + 10;
                        }
                    }

                    send_this_time=true;
                    for val in wdopr.feeditems.values() {
                        if val.now_feed>=val.feed_limit{
                            send_this_time=false;
                            if close_watchdog  {
                                println!("wathchdog :{} long time no run ",val.name);
                            }

                        }
                    }
                    if send_this_time{
                       // println!("wathchdog feed once");
                       let _= wd.write("1".as_bytes()).await;
                       let _= wd.flush().await;
                    }else{
                        if close_watchdog  {
                            let _=wd.write("1".as_bytes()).await;
                            let _=wd.flush().await;
                        }
                       // println!("wathchdog not feed once");
                    }
                }

                pub_inof=to_each_handle_pubch_wd.recv()=>{
                    if let Ok(comdata::ExData::CfgData(bxo_cfgdata))=pub_inof{
                         close_watchdog=bxo_cfgdata.wd_cfg.close_watchdog;
                    //todo
                    }

                }


                inputframe = wdrec.recv() => {
                    /*
                    1 对应的条目计数清零
                    2 判断所有检测条目满足条件后
                    再发送**/
                    if let Some(getwdframe)= inputframe{
                        match getwdframe{
                            WdFrame::Feed(  feed_id )=>{
                                feeidu8=feed_id as u8;
                                if wdopr.feeditems.contains_key(  &feeidu8  )    {
                                    wdopr.feeditems.get_mut(&feeidu8  ).map(|entry| entry.now_feed=0);
                                }
                            }
                            WdFrame:: Reg(feed_item)=>{
                                wdopr. reg_new_item_total(feed_item);
                            }

                        }
                    }else {/* 通知通道已经结束 ，结束本看门狗任务 */
                        return Ok(());
                    }

                }
                _=shutdown.recv()=>{
                    let _=wd.write("V".as_bytes()).await;

                    return Ok(());
                }
            }
        }
    } else {
        println!("open wathdog failed");
    }

    Ok(())
}

//向看门狗注册模块的函数
pub fn reg_mod_to_wd(
    wd_tx: mpsc::Sender<WdFrame>,
    feed_id: FeedId,
    name: String,
    feed_limit: u32,
    now_feed: u32,
) {
    let _=wd_tx.try_send(WdFrame::Reg(FeedItem {
        feed_id,
        name,
        feed_limit,
        now_feed,
    }));
}
