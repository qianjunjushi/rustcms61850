use crate::utils;
use anyhow::{bail, Context};
use mac_address::MacAddress;
use quick_xml::{
    events::{BytesEnd, BytesStart, BytesText, Event},
    Reader,
};
use std::collections::HashMap;
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::str::from_utf8;
use std::str::FromStr;
use std::sync::Barrier;
use tokio::fs;
/************************************************************************/
/*			目录					*/
/* 1 入口函数 */
/* 2 scl 相关结构体 */
/* 3 解析相关细节结构体 及函数 */
/* 4 解析中间态 辅助结构体 */
/************************************************************************/
pub const SCL_PARSE_MODE_CID: u32 = 0; /* default SCL parse mode	*/
pub const SCL_PARSE_MODE_SCD: u32 = 1;
/* Defined values for "nameStructure" attribute	*/
pub const SCL_NAMESTRUCTURE_IEDNAME: u32 = 0; /* value="IEDName"	*/
pub const SCL_NAMESTRUCTURE_FUNCNAME: u32 = 1; /* value="FuncName"	*/
pub const SX_MAX_ITEMS_PER_TABLE: usize = 50;

pub const SX_PARSING_OK: u32 = 0;
pub const SX_USER_ERROR: u32 = 1;
pub const SX_STRUCT_NOT_FOUND: u32 = 2;
pub const SX_REQUIRED_TAG_NOT_FOUND: u32 = 3;
pub const SX_DUPLICATE_NOT_ALLOWED: u32 = 4;
pub const SX_EMPTY_TAG_NOT_ALLOWED: u32 = 5;
pub const SX_XML_NEST_TOO_DEEP: u32 = 6;
pub const SX_XML_BUFFER_OVER_MAX: u32 = 7;
pub const SX_XML_MALFORMED: u32 = 8;
pub const SX_FILE_NOT_FOUND: u32 = 9;
pub const SX_END_PARSING: u32 = 10; /* for partial parsing	*/
pub const SX_ELEMENT_TBL_TOO_BIG: u32 = 11;
pub const SX_ERR_ATTR_NOT_FOUND: u32 = 12; /* ok if optional	*/
pub const SX_ERR_REQUIRED_ATTR_NOT_FOUND: u32 = 13;
pub const SX_ERR_ALLOC: u32 = 14;

/* defines for 'reason' */
pub const SX_ELEMENT_START: u32 = 1;
pub const SX_ELEMENT_END: u32 = 2;

/* Normal errors - continue with parse */
pub const SX_ERR_CONVERT: u32 = 100;

pub const SD_TRUE: u32 = 1;
pub const SD_FALSE: u32 = 0;
pub const SD_SUCCESS: u32 = 0;
pub const SD_FAILURE: u32 = 1;
pub const SD_BIG_ENDIAN: u32 = 0;
pub const SD_LITTLE_ENDIAN: u32 = 1;

pub const MAX_IDENT_LEN: usize = 64; /* length of an Identifier variable	*/

/* Define larger PSEL,SSEL for compatibility with existing applications.*/
pub const MAX_PSEL_LEN: usize = 16; /* International Std Profile recommends 4*/
pub const MAX_SSEL_LEN: usize = 16; /* GOSIP Ver2 recommends len of 2	*/

/* Define larger TSEL for compatibility with existing applications.	*/
pub const MAX_TSEL_LEN: usize = 32; /* GOSIP Ver2 recommends len of 2	*/

pub const MAX_OBJID_COMPONENTS: usize = 16;

pub const MAX_VALKIND_LEN: usize = 4; /* Spec, Conf, RO, or Set		*/

pub const CLNP_MAX_LEN_MAC: usize = 6; /* Max len of MAC addr*/

pub const MAX_CDC_LEN: usize = 50; /* SPS, DPS, etc. (CURVE is longest	*/
/* predefined CDC but user may define others)*/
pub const MAX_FC_LEN: usize = 2; /* ST, MX, etc.				*/

/* This def used for flattened leaf names (longer to allow array indices)*/
/* Allow 7 extra char for 5 digit array index & brackets, like [10000]	*/
pub const MAX_FLAT_LEN: usize = MAX_IDENT_LEN + 7;

pub const MVL61850_MAX_RPTID_LEN: usize = 65;
pub const MVL61850_MAX_OBJREF_LEN: usize = 129; /* Value specified by Tissue 141*/

pub const SX_MAX_STACK_LEVEL: usize = 1000;

pub const SX_MAX_XML_NEST: usize = 30;

/* elementFlags defines; bitmasked */
/*必须要有开始     */
pub const SX_ELF_CSTART: u32 = 0x0001;
pub const SX_ELF_CEND: u32 = 0x0002;
/*首尾必须都有     */
pub const SX_ELF_CSTARTEND: u32 = 0x0003;

pub const SX_ELF_RPT: u32 = 0x0008;
pub const SX_ELF_OPT: u32 = 0x0004;
pub const SX_ELF_OPTRPT: u32 = 0x000C;

pub const SX_ELF_EMPTYOK: u32 = 0x0010;

pub const SCL_ATTR_OPTIONAL: bool = false; /* attribute is optional	*/
pub const SCL_ATTR_REQUIRED: bool = true; /* attribute is required	*/

/* Use "bit" macros (BSTR_BIT_*) to access each individual bit.		*/
pub const TRGOPS_BITNUM_RESERVED: usize = 0;
pub const TRGOPS_BITNUM_DATA_CHANGE: usize = 1; /* "dchg" in some specs	*/
pub const TRGOPS_BITNUM_QUALITY_CHANGE: usize = 2; /* "qchg" in some specs	*/
pub const TRGOPS_BITNUM_DATA_UPDATE: usize = 3; /* "dupd" in some specs	*/
pub const TRGOPS_BITNUM_INTEGRITY: usize = 4; /* "period" in 61850-6	*/
pub const TRGOPS_BITNUM_GENERAL_INTERROGATION: usize = 5;

pub const OPTFLD_BITNUM_RESERVED: usize = 0;
pub const OPTFLD_BITNUM_SQNUM: usize = 1;
pub const OPTFLD_BITNUM_TIMESTAMP: usize = 2;
pub const OPTFLD_BITNUM_REASON: usize = 3;
pub const OPTFLD_BITNUM_DATSETNAME: usize = 4;
pub const OPTFLD_BITNUM_DATAREF: usize = 5;
pub const OPTFLD_BITNUM_BUFOVFL: usize = 6;
pub const OPTFLD_BITNUM_ENTRYID: usize = 7;
pub const OPTFLD_BITNUM_CONFREV: usize = 8;
pub const OPTFLD_BITNUM_SUBSEQNUM: usize = 9; /* segmentation in 61850-8-1*/

/* Bit numbers in OptFlds bitstring (configured by SmvOpts in SCL file)	*/
pub const SVOPT_BITNUM_REFRTM: usize = 0;
pub const SVOPT_BITNUM_SMPSYNCH: usize = 1; /* Ignored for Edition 2	*/
pub const SVOPT_BITNUM_SMPRATE: usize = 2;
pub const SVOPT_BITNUM_DATSET: usize = 3; /* Edition 2 only	*/
pub const SVOPT_BITNUM_SECURITY: usize = 4; /* Edition 2 only	*/

/* These defines used in SCL_DA struct to differentiate between structs	*/
/* containing DA info and structs containing SDO info.			*/
pub const SCL_OBJTYPE_DA: u32 = 0;
pub const SCL_OBJTYPE_SDO: u32 = 1;

/************************************************************************/
/*			1入口函数 start					*/
/************************************************************************/
pub async fn scl_parse(
    xmlfilename: &str,
    iedname: &str,
    accesspointname: &str,
) -> crate::Result<SclInfo> {
    scl_parse_cid(xmlfilename, iedname, accesspointname, None).await
}

pub async fn scl_parse_cid(
    xmlfilename: &str,
    iedname: &str,
    accesspointname: &str,
    options: Option<SclOptions>, /* miscellaneous parser options		*/
                                 /* may be NULL if no options needed	*/
) -> crate::Result<SclInfo> {
    //todo
    /* start with clean struct.	*/
    let mut scldecctrl = SclDecCtrl::default();

    /* If "iedName" contains illegal characters, don't even parse.	*/
    /* It must match an "IED name" in the file which also must be legal.	*/
    if !chk_mms_ident_legal(iedname) {
        bail!(format!(
            "Illegal character in IED name {} passed to SCL parser. Cannot parse.",
            iedname
        ))
    }

    scldecctrl.iedname = iedname.to_string();
    scldecctrl.accesspointname = accesspointname.to_string();
    scldecctrl.accesspointfound = false;

    /* Set "parseMode" to control parsing later.	*/
    scldecctrl.parsemode = SCL_PARSE_MODE_CID;
    if let Some(options) = options {
        scldecctrl.sclinfo.options = options;
    }
    if !chk_mms_ident_legal(&iedname) {
        bail!(format!("Error:iedname iilegal {}", iedname));
    }

    let icdstr = fs::read_to_string(xmlfilename)
        .await
        .context(format!("open icd file failed   "))?;
    let mut reader = Reader::from_str(icdstr.as_str());
    reader.trim_text(true);

    //let mut txt = Vec::new();
    //let mut ctx=ICD_PARSE_CONTEXT;
    let scl_tb_index_vec = vec![0];

    // let bytesRead=cfgData.len();

    let mut ctx = IcdParseContext2::init_data();
    ctx.scl_dec_ctrl = scldecctrl;

    ctx.sx_push(scl_tb_index_vec.clone());
    let mut buf = Vec::new();
    loop {
        if ctx.errcode != SD_SUCCESS && ctx.errcode != SX_ERR_CONVERT {
            bail!(format!("err happened when parse icd ,code {}", ctx.errcode));
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let start_tag_info = get_start_tag_info(e, &reader)?;
                ctx.sxstartelement(start_tag_info);
            }
            Ok(Event::End(ref e)) => {
                let end_tag_info = get_end_tag_info(e, &reader)?;
                ctx.sxendelement(end_tag_info);
            }
            Ok(Event::Empty(ref e)) => {
                let start_tag_info = get_start_tag_info(e, &reader)?;
                let end_tag_info = TagInfo {
                    tag: start_tag_info.tag.clone(),
                    atts: HashMap::new(),
                };
                ctx.sxstartelement(start_tag_info);
                ctx.sxendelement(end_tag_info);
            }
            Ok(Event::Text(e)) => match e.unescape() {
                Ok(txt) => {
                    ctx.op_entry_text = Some(txt.into_owned());
                }
                Err(e) => {
                    println!("get txt info err {}", e);
                    break;
                }
            },
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => (),
            //          /// Start tag (with attributes) `<tag attr="value">`.
            // Start(BytesStart<'a>),
            // /// End tag `</tag>`.
            // End(BytesEnd<'a>),
            // /// Empty element tag (with attributes) `<tag attr="value" />`.
            // Empty(BytesStart<'a>),
            // /// Character data between `Start` and `End` element.
            // Text(BytesText<'a>),
            // /// Comment `<!-- ... -->`.
            // Comment(BytesText<'a>),
            // /// CData `<![CDATA[...]]>`.
            // CData(BytesText<'a>),
            // /// XML declaration `<?xml ...?>`.
            // Decl(BytesDecl<'a>),
            // /// Processing instruction `<?...?>`.
            // PI(BytesText<'a>),
            // /// Doctype `<!DOCTYPE...>`.
            // DocType(BytesText<'a>),
            // /// End of XML document.
            // Eof,
        }
        buf.clear();
    }
    if ctx.errcode == 0 {
        return Ok((*ctx.scl_dec_ctrl.sclinfo).clone());
    } else {
        bail!("pare icd failed");
    }
}

/************************************************************************/
/*			1入口函数 end					*/
/************************************************************************/

/************************************************************************/
/*			2 scl 相关结构体 start					*/
/************************************************************************/
//解析的时候选配使用 好像实际没有使用
#[derive(Default, Clone, Debug)]
pub struct SclOptions {
    /*0 表示是根据scl 自己标注的来
    1 表示强制是版本1
    2 表示强制版本2
    我们这里没有给定option 所以默认 0     */
    pub forceedition: u32, /* 0 = use edition detected in SCL file	*/
    /* 1 = force Edition 1 parsing		*/
    /* 2 = force Edition 2 parsing		*/
    /* NOTE: "includeOwner" should NOT be used if Tissue 807 is approved.	*/
    /*       It should only be used as an alternative way to control	*/
    /*       inclusion of "Owner" until Tissue 807 is resolved.		*/
    pub includeowner: bool, /* control inclusion of "Owner" in RCBs.*/
}

/*1.1 scl/header     */
#[derive(Default, Clone, Debug)]
pub struct SclHeader {
    /* NOTE: only required elements included here. Add optional elements as needed.*/
    /*好像没什么用 反正没见过用过     */
    pub id: String,
    /*固定值 不用管     */
    pub namestructure: u32,
}
/*1.2.1  scl/communication/subnet
因为 comunicaiton 最多一个 所以把他提出来了  */
/* Data from "Subnetwork" element	*/
#[derive(Default, Clone, Debug)]
pub struct SclSubnet {
    /*这个subnet 里面名字好没有存在感
    里面重要的 东西是里面cap
    可以这么理解 subnet 里面存放了好多cap
    cap 里面存放了3种东西
    smv gse  addr
    要查找的时候 必须遍历 subnet  嵌套循环 cap
    在里面查找
    3种需要匹配 cap 里面 iedname/apname
    其中iedname 必须有  apname 如果没有提供表示适配所有
    1 smv要匹配smv 里面iedname/apname +ldinst 和cbname
    2 addr 匹配 外部的 iedname/apname
    3 gse 匹配 gse里面的 iedname/apname（！！！apname 可以全部适配）+ldinst 和cbname*/
    pub name: String,
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub rtype: String,

    pub cap_vec: Vec<SclCap>, /* head of list of ConnectedAP defs	*/
}
/*1.2.1  scl/communication/subnet/cap */
/* Data from "ConnectedAP" element	*/
#[derive(Default, Clone, Debug)]
pub struct SclCap {
    /* 注意 这个iedname 和apname 都来自共同的父亲  connectedap 的属性 */
    pub iedname: String,
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub apname: String,
    /*cap 可以理解为 一个访问点
    他具有一个地址
    多个gse
    多个smv     */
    pub address: SclAddress,  /* one address. NO LINKED LIST.	*/
    pub gse_vec: Vec<SclGse>, /* head of list of GSE defs	*/
    pub smv_vec: Vec<SclSmv>, /* head of list of SMV defs	*/
}

#[derive(Default, Clone, Debug)]
pub struct MmsObjId {
    pub num_comps: u32,   /* number of objid components	*/
    pub comps: [i16; 16], /* identifier components	*/
}
#[derive(Default, Clone, Debug)]
pub struct AeTitle {
    pub ap_title_pres: bool,  /* present flag                 */
    pub ap_title: MmsObjId,   /* ap title                     */
    pub ae_qual_pres: bool,   /* present flag                 */
    pub ae_qual: i32,         /* ae qualifier                 */
    pub ap_inv_id_pres: bool, /* present flag                 */
    pub ap_inv_id: i32,       /* ap invocation id             */
    pub ae_inv_id_pres: bool, /* present flag                 */
    pub ae_inv_id: i32,       /* ae invocation id             */
}
// <Address>
//     <P type="IP">127.0.0.1</P>
//     <P type="IP-SUBNET">255.255.255.0</P>
//     <P type="IP-GATEWAY">10.0.0.101</P>
//     <P type="OSI-PSEL">00000001</P>
//     <P type="OSI-SSEL">0001</P>
//     <P type="OSI-TSEL">0001</P>
// </Address>
#[derive(Clone, Debug)]
pub struct SclAddress {
    pub ae_title: AeTitle, /* includes ap title, ae qualifier, etc.	*/

    pub psel_len: u32,
    pub psel: String,
    pub ssel_len: u32,
    pub ssel: String,
    pub tsel_len: u32,
    pub tsel: String,
    pub ip: Ipv4Addr, /* ip addr (network byte order)	*/
}
impl Default for SclAddress {
    fn default() -> Self {
        SclAddress {
            ae_title: AeTitle::default(), /* includes ap title, ae qualifier, etc.	*/

            psel_len: 0,
            psel: String::new(),
            ssel_len: 0,
            ssel: String::new(),
            tsel_len: 0,
            tsel: String::new(),
            ip: Ipv4Addr::new(192, 168, 0, 15),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct SclDo {
    // <DO name="Mod" type="INC"/>
    /* 名字 和 类型 类型   类型定义有些事自定义 有些是规范定义  */
    pub name: String,  /* data object name		*/
    /*这个type 关联的是dotype 里面的 id     */
    pub rtype: String, /* data object type		*/
}

#[derive(Default, Clone, Debug)]
pub struct SclLntype {
    /*也就是lntype 的名字    */
    pub id: String,         /* name used to reference this LN Type*/
    /*类型     */
    pub lnclass: String,    /* logical node class		*/
    pub do_vec: Vec<SclDo>, /* head of list of DO	*/
    /* scl_lntype_add_do adds to list	*/
    pub type_id: u32, /* Initialized by "scl2_datatype_create_all"*/
}

#[derive(Default, Clone, Debug)]
pub struct SclDotype {
    /*用来关联lNtype 里面的  type   */
    pub id: String,  /* name used to reference this DO Type	*/
    pub cdc: String, /* CDC name				*/
    /*里面其实 只能是da 或者sdo sdo 里面只能是sdo 或者da
    然后这里取出来 构成结构体     */
    pub da_vec: Vec<SclDa>, /* head of list of DA or SDO		*/
                     /* scl_dotype_add_da OR			*/
                     /* scl_dotype_add_sdo adds to list	*/
}
#[derive(Default, Clone, Debug)]
pub struct SclDatype {
    pub id: String, /* name used to reference this da type*/

    pub bda_vec: Vec<SclBda>, /* head of list of BDA	*/
                              /* scl_datype_add_bda adds to list	*/
}
#[derive(Default, Clone, Debug)]
pub struct SclEnumtype {
    pub id: String, /* name used to reference this DA Type*/
    pub enumval_vec: Vec<SclEnumval>, /* head of list of EnumVal	*/
                    /* scl_enumtype_add_enumval adds to list*/
}
/************************************************************************/
/*			SCL_SERV_OPT					*/
/* Options for a Server (NOT configured by SCL).			*/
/************************************************************************/
#[derive(Default, Clone, Debug)]
pub struct SclServOpt {
    /* Report configuration parameters.		*/
    pub reportscanratems: u32, /* report scan rate (millisec)		*/
    pub brcb_bufsize: u32,     /* brcb buffer size			*/
    /* log configuration parameters.		*/
    pub logscanratems: u32, /* log scan rate (millisec)		*/
    pub logmaxentries: u32, /* Max number of Log entries allowed	*/
}

#[derive(Default, Clone, Debug)]
pub struct SclServer {
    /*这个不是解析出来的，好像scd 的时候使用  外部配置传进来的     */
    pub serv_opt: SclServOpt, /* options not configured by SCL	*/
    /*这个是icd 里面解析出来的 一个server 多个 逻辑设备     */
    pub ld_vec: Vec<SclLd>, /* head of list of LDevice defs		*/
    /* for this Server			*/
    /*下面两个都是 ied 和ap的属性决定的 表示你属于这个  同时也是根据这个来索引     */
    pub iedname: String, /* IED name for this Server	*/
    pub apname: String,  /* AccessPoint name for this Server*/
    //todo
    //MVL_VMD_CTRL *vmd_ctrl;	/* VMD created for this Server		*/
    /*注意 这里面不是内部的解析 而是前面的解析 然后每个server 里面放了一份     */
    pub scl_services: SclServices, /* Info from "Services" section of SCL	*/
}

//scl 文件解析出来的汇总信息
#[derive(Default, Clone, Debug)]
pub struct SclInfo {
    pub edition: u32, /* 0 (default) means edition 1		*/
    /* 2 means edition 2			*/
    /* other editions not supported.	*/
    //没有提供 所以使用默认值 无关紧要
    pub options: SclOptions, /* parser options passed by user	*/
    /*对应的 head节点     */
    pub header: SclHeader, /* info from "header" section of scl file*/
    /*communication 节点里面的东西
    里面主要存放的是一些地址信息  */
    /* subnetwork definitions from (from communication section)		*/
    pub subnet_vec: Vec<SclSubnet>, /* head of list of subnetwork defs	*/
    /*template 节点里面的东西     */
    /* logical node type definitions (from datatypetemplates section)	*/
    pub lntype_vec: Vec<SclLntype>, /* head of list	of lnodetype defs	*/
    pub dotype_vec: Vec<SclDotype>, /* head of list of dotype defs		*/
    pub datype_vec: Vec<SclDatype>, /* head of list of datype defs		*/
    pub enumtype_vec: Vec<SclEnumtype>, /* head of list of enumtype defs	*/

    /*ied 节点里面的信息 其中 包含iedname 和 accesspointname
    但是这里都没有记录 是因为startupcfg 里面提供了这两个信息
    而且会和scl 文件进行对比 判断     */
    /* server definitions (from "server" section)				*/
    /*这个是ied里面的 ap 下面的
    ied 和 ap 决定下面所有的iedname  和apname     */
    /*注意 一个ap 下面只能有一个server  这里就当做多个ap     */
    pub server_vec: Vec<SclServer>, /* head of list of server defs		*/

    pub datatype_create_done: bool, /* flag set by scl2_datatype_create_all*/
    pub ld_create_done: bool,       /* flag set by scl2_ld_create_all*/

                                    /* parameters below used only when paremode==scl_parse_mode_scd_filtered.*/
                                    // scl_serv_cfg *scl_serv_cfg_arr;	/* array of servers to configure*/
                                    // st_uint       scl_serv_cfg_num;	/* number of servers in array	*/
                                    // st_char **scl_iedtype_cfg_arr;	/* array of iedtypes to configure*/
                                    // st_uint     scl_iedtype_cfg_num;	/* number of iedTypes in array	*/
}
// <GSE ldInst="C1" cbName="GsseTest">
//     <Address>
//         <P type="MAC-Address">01-0C-CD-01-00-02</P>
//         <P type="APPID">5000</P>
//         <P type="VLAN-PRIORITY">4</P>
//     </Address>
// </GSE>
/* Data from "GSE" element (inside "ConnectedAP" element)	*/
#[derive(Default, Clone, Debug)]
pub struct SclGse {
    /*参照的ld的名称     */
    pub ldinst: String,
    /*测量的说明性内容标志     */
    pub cbname: String,
    pub mac: MacAddress, /* Multicast MAC address	*/
    pub appid: u32,
    pub vlanpri: u32,
    pub vlanid: u32,
    pub mintime: u32, /* Minimum GOOSE retrans time (ms)	*/
    pub maxtime: u32, /* Maximum GOOSE retrans time (ms)	*/
}
/* Data from "SMV" element (inside "ConnectedAP" element)	*/
// <SMV ldInst="C1" cbName="Volt">
//     <Address>
//         <P type="MAC-Address">01-0C-CD-04-00-01</P>
//         <P type="APPID">4000</P>
//         <P type="VLAN-ID">123</P>
//         <P type="VLAN-PRIORITY">4</P>
//     </Address>
// </SMV>
#[derive(Default, Clone, Debug)]
pub struct SclSmv {
    /*参照的ld的名称     */
    pub ldinst: String,
    /*测量的说明性内容标志     */
    pub cbname: String,
    pub mac: MacAddress, /* Multicast MAC address	*/
    pub appid: u32,
    pub vlanpri: u32,
    pub vlanid: u32,
}
#[derive(Default, Clone, Debug)]
pub struct SclLd {
    /*可能你不信 但是这个为了使用设计的
    其实是拼接的
    domain name = IED name + LDevice inst    */
    pub domname: String, /* domain name (constructed)	*/
    pub desc: String,    /* description (optional)*/
    /* may be long so allocate if present*/
    /*这个才是真正的名字     */
    pub inst: String, /* ld inst name		*/
    pub ln_vec: Vec<SclLn>, /* head of list of LN	*/
                      /* NOTE: AccessControl in LDevice is ignored	*/
} /* Logical Device (LDevice in SCL)*/
#[derive(Default, Clone, Debug)]

pub struct SclFcda {
    /*组合 公式 为 iedName+ ldinst     */
    pub domname: String, /* domain name (constructed)	*/
    /*关联的哪个LD  ld的索引是inst     */
    pub ldinst: String,

    /*下面几个 prefix +lnclass+lninst +fc+doname+datame   有另外的使用场景
    但是这里只组合了 domname   */
    pub prefix: String,
    pub lninst: String,
    pub lnclass: String,
    pub doname: String,
    pub daname: String,
    pub fc: String, /* st, mx, etc.			*/
    /*ix 是版本2才有的字段     */
    pub ix: String, /* array index (5 digits max)	*/
}
#[derive(Default, Clone, Debug)]
pub struct SclGcb {
    pub name: String, /* Name of CB. Used to construct*/
    /* GoCBRef or GsCBRef		*/
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String, /* for GOOSE only	*/
    /* used to construct GOOSE DatSet*/
    pub confrev: u32,  /* for GOOSE only	*/
    pub isgoose: bool, /* SD_TRUE if "GOOSE", SD_FALSE if "GSSE"*/
    pub appid: String, /* for GOOSE only	*/
    /* maps to GoID in 61850-7-2	*/
    pub subscribed: bool, /* user subscribed to this GCB	*/
                          /* The SCL file may also contain one or more "IEDName" elements to	*/
                          /* indicate IEDs that should subscribe for GOOSE data. We have no	*/
                          /* way to use this information, so it is ignored.			*/
}

#[derive(Default, Clone, Debug)]
pub struct SclDataset {
    /*这个名字很重要 是必须得  报告和日志都根据这个名字 来定义      */
    pub name: String, /* dataset name		*/
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub fcda_vec: Vec<SclFcda>, /* head of list of FCDA	*/
}
#[derive(Default, Clone, Debug)]
pub struct SclSgcb {
    pub desc: String, /* description (optional)		*/
    /* may be long so allocate if present	*/
    pub numofsgs: u32, /* mandatory	*/
    pub actsg: u32,    /* optional	*/
}

#[derive(Default, Clone, Debug)]
pub struct SclExtref {
    /* Pointers are first just to reduce structure padding.	*/
    pub desc: String, /* description				*/
    /* may be long so allocate if present	*/
    pub intaddr: String, /* internal address			*/
    /* may be long so allocate if present	*/
    /* max lengths of these attributes set by scl schema.	*/
    pub iedname: String,
    pub ldinst: String,
    pub prefix: String,
    pub lnclass: String,
    pub lninst: String,
    pub doname: String,
    pub daname: String,
    pub servicetype: String,
    pub srcldinst: String,
    pub srcprefix: String,
    pub srclnclass: String,
    pub srclninst: String,
    pub srccbname: String,
}

#[derive(Default, Clone, Debug)]
pub struct SclLn {
    /*也是组合的名字  组合公式  prefix + lnclass +inst    */
    pub varname: String, /* variable name (constructed)	*/
    pub desc: String,    /* description (optional)*/
    /* may be long so allocate if present*/
    /*z注意这里的 lntype 对应的 模板里面lntype->id
    某种程度上讲 就是 lntype 的名字     */
    pub lntype: String, /* ln type name		*/
    /*感觉这里只是单纯解析 但是实际上应该和 模板里面lntype->lnclass 一致     */
    pub lnclass: String, /* ln class name	*/
    /* for ln0, must be "lln0"	*/
    pub inst: String, /* ln inst name			*/
    /* for ln0, must be "" (empty string)*/
    pub prefix: String, /* ln prefix name	*/
    /* for lno, ignored	*/
    pub dai_vec: Vec<SclDai>,         /* head of list of dai	*/
    pub dataset_vec: Vec<SclDataset>, /* head of list of dataset	*/
    pub rcb_vec: Vec<SclRcb>,         /* head of list of rcb (report control)	*/
    pub lcb_vec: Vec<SclLcb>,         /* head of list of lcb (log control)	*/
    pub gcb_vec: Vec<SclGcb>,         /* head of list of gcb (goose control)	*/
    pub svcb_vec: Vec<SclSvcb>,       /* head of list of svcb (sampled value control)*/
    pub sgcb: Box<SclSgcb>,           /* sgcb (setting group control)(only 1 allowed)*/
    pub extref_vec: Vec<SclExtref>,   /* head of list of extref (in inputs)	*/
    /* note: in ln or ln0: inputs ignored		*/
    /* note: in ln0: sclcontrol ignored		*/
    pub type_id: u32, /* Initialized by "scl2_datatype_create_all"*/

                      //todo //MVL_VAR_ASSOC *mvl_var_assoc;	/* MVL Variable Association created from LN info*/
} /* Logical Node (LN or LN0 in SCL)	*/

#[derive(Default, Clone, Debug)]
pub struct SclRcb {
    /*rcb的，名字     */
    pub name: String,
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String,
    /*周期上送时间     */
    pub intgpd: u32,
    /*报告id     */
    pub rptid: String,
    /*不可思议 这个竟然是必选字段 因为如果客户需要 也要返回这个值     */
    pub confrev: u32,
    /*是否缓存     */
    pub buffered: bool, /* TRUE if this is buffered RCB	*/
    /*缓存时间     */
    pub buftime: u32,
    pub trgops: u8, /* 8-bit bitstring			*/
    /* boolean vals from SCL file		*/
    /* (dchg, qchg, dupd, & period)		*/
    /* used to set bits in TrgOps bitstring	*/
    pub optflds: [u8; 2], /* 9-bit bitstring			*/
    /* boolean vals from SCL file		*/
    /* (seqnum, timeStamp, dataSet,		*/
    /* reasoncode, dataRef, bufOvfl,	*/
    /* entryid, configRef)			*/
    /* segmentation boolean is ignored	*/
    /* used to set bits in OptFlds bitstring*/
    pub maxclient: u32, /* value of "RptEnabled max" attr.	*/
} /* Report Control Block	*/

#[derive(Default, Clone, Debug)]
pub struct SclLcb {
    /*日志控制块的名字 区别 日志的名字     */
    pub name: String,
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String,
    pub intgpd: u32,
    /*日志的名称     */
    pub logname: String,
    pub logena: bool,
    /*米有报告控制那么多  只有个原因码     */
    pub reasoncode: bool,
    pub trgops: u8, /* 8-bit bitstring			*/
                    /* Boolean vals from SCL file		*/
                    /* (dchg, qchg, dupd, & period)		*/
                    /* used to set bits in TrgOps bitstring	*/
}
#[derive(Default, Clone, Debug)]
pub struct SclSvcb {
    pub name: String,
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String,
    /* "smvid" big enough for edition 2, but only 65 char allowed for edition 1*/
    pub smvid: String,
    pub smprate: u32,
    pub nofasdu: u32,
    pub confrev: u32,
    pub multicast: bool, /* true if this is msvcb		*/
    pub optflds: u8,     /* 8-bit bitstring			*/
    /* boolean vals from "smvopts" in scl	*/
    /* (samplerate, etc.)			*/
    /* used to set bits in this bitstring	*/
    pub securitypres: bool, /* smvopts security flag	*/
    pub datarefpres: bool,  /* smvopts dataref flag		*/
    /* for edition 2 only	*/
    pub smpmod: i8, /* smpPerPeriod, SmpPerSec, or SecPerSmp*/
                    /* converted to Enumerated value	*/
} /* Sampled Value Control Block	*/

#[derive(Default, Clone, Debug)]
pub struct SclEnumval {
    pub ord: i32, /* ord attribute	*/
    /* if string fits in enumvalbuf, it is copied there & enumval is set	*/
    /* to point to it. else, enumval is allocated & string is copied to it.*/
    //st_char *enumval:String,		/* enumval pointer		*/
    pub enumval: String, /* EnumVal buffer		*/
}
/* "scl_dai_add" allocates this struct, fills it in,			*/
/* and adds it to the linked list "dai_vec" in SCL_LN.			*/
/* The "flattened" name must be constructed from the "name" & "ix"	*/
/* attribute of the DOI and DAI and possibly the intervening SDI,	*/
/* where "ix" is an array index (we'll need some new flattened name	*/
/* syntax to handle the array index).					*/
/* The "accessControl" attr of DOI is ignored (don't know what it means).*/
/* The "desc" attr of DOI, SDI, & DAI are ignored (not useful).		*/
#[derive(Default, Clone, Debug)]
pub struct SclDai {
    /*注意 这里 doi 里面含有sdi和dai  sdi 里面含有sdi和dai
    最后结果都是dai     */
    /*dai 只能是值了 可以关联 短地址  */
    /*注意 这个是Do 一层所有的累加名称name[ix]    */
    pub flattened: String, /* flattened attribute name	*/
    /*dai 表示一个实际的值 或者多个值的一个
    val 就表示实际的值
    如果scldai 有group 那么就构成一个sgval 放进去 
    如果没有group  就表示只能是一个 */
    /* constructed from "name" & "ix"*/
    /* from doi, sdi, & dai		*/
    pub val: String, /* attribute value text		*/
    /* 和上面是二选一*/
    pub sgval_vec: Vec<SclSgVal>, /* linked list of setting group	*/
    /* initial values		*/
    pub saddr: String, /* from dai			*/
    /*默认 字符串 “set”     */
    pub valkind: String, /* from DAI			*/
}
#[derive(Default, Clone, Debug)]
pub struct SclSgVal {
    pub sgroup: u32, /* setting group for this val	*/
    pub val: String, /* Val text			*/
                     /* allocate appropriate size buffer*/
}
/* This structure should be allocated and filled in by the function	*/
/* "scl_dotype_add_da" OR "scl_dotype_add_sdo", and possibly modified by the optional	*/
/* function "scl_dotype_add_da_val".					*/
/* NOTE: the same structure must be used for DA or SDO because each must	*/
/* be put on the same linked list in the order they are read from the SCL file.*/
/* Most of the parameters are relevant only for DA elements. They are	*/
/* ignored if this is an SDO (i.e. objtype=SCL_OBJTYPE_SDO).		*/
#[derive(Default, Clone, Debug)]
pub struct SclDa {
    pub objtype: u32, /* SCL_OBJTYPE_DA or SCL_OBJTYPE_SDO	*/
    pub name: String, /* DA or SDO name		*/
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub saddr: String,   /* for DA only: DA sAddr	*/
    pub btype: String,   /* for DA only: DA bType	*/
    pub valkind: String, /* for DA only: Spec, Conf, RO, or Set	*/
    pub rtype: String,   /* for DA: needed if bType="Struct" or "Enum"*/
    /* for SDO: required		*/
    pub count: u32, /* for DA only: num array entries*/
    pub fc: String, /* for DA only: functional constraint	*/
    pub dchg: bool, /* for DA only: TrgOp (data change)	*/
    pub qchg: bool, /* for DA only: TrgOp (quality change)	*/
    pub dupd: bool, /* for DA only: TrgOp (data update)	*/

    /* The "Val" and "sGroup" parameters are only set if the SCL file contains the
     * optional "Val" element, in which case "scl_dotype_add_da_val" is called.
     */
    pub val: String, /* for DA only: attribute value text	*/
    /* allocate appropriate size buffer*/
    pub sgval_vec: Vec<SclSgVal>, /* for DA only: linked list of	*/
                                  /* Setting Group initial values	*/
}
/* This structure should be allocated and filled in by the function	*/
/* "scl_datype_add_bda".						*/
#[derive(Default, Clone, Debug)]
pub struct SclBda {
    pub name: String, /* data attribute name		*/
    pub desc: String, /* description (optional)*/
    /* may be long so allocate if present*/
    pub saddr: String,   /* for da only: da saddr	*/
    pub btype: String,   /* data attribute type		*/
    pub valkind: String, /* spec, conf, ro, or set	*/
    pub rtype: String,   /* only used if btype="struct" or "enum"*/
    pub count: u32,      /* for da only: num array entries*/

    /* the "val" and "sgroup" parameters are only set if the scl file contains the
     * optional "val" element, in which case "scl_datype_add_bda_val" is called.
     */
    pub val: String, /* attribute value text		*/
    /* allocate appropriate size buffer*/
    pub sgval_vec: Vec<SclSgVal>, /* linked list of Setting Group	*/
                                  /* initial values		*/
} /* Basic Data Attribute		*/

#[derive(Default, Clone, Debug)]
pub struct SclReportsettings {
    /* These may be "Dyn", "Conf", or "Fix". No other values allowed.	*/
    pub cbname: String,
    pub datset: String,
    pub rptid: String,
    pub optfields: String,
    pub buftime: String,
    pub trgops: String,
    pub intgpd: String,
    pub resvtms: bool,
    pub owner: bool, /* proposed in Tissue 807 */
}

#[derive(Default, Clone, Debug)]
pub struct SclServiceWithMax {
    pub enabled: bool,
    pub max: u32,
}
#[derive(Default, Clone, Debug)]
pub struct SclServices {
    /* Simple entries just map to booleans.	*/
    pub getdirectory: bool,
    pub getdataobjectdefinition: bool,
    pub dataobjectdirectory: bool,
    pub getdatasetvalue: bool,
    pub setdatasetvalue: bool,
    pub datasetdirectory: bool,
    pub readwrite: bool,
    pub timeractivatedcontrol: bool,
    pub getcbvalues: bool,
    pub gsedir: bool,
    pub filehandling: bool,
    pub confldname: bool,
    /* More complicated entries need special mappings.	*/
    pub conflogcontrol: SclServiceWithMax,
    pub goose: SclServiceWithMax,
    pub gsse: SclServiceWithMax,
    pub smvsc: SclServiceWithMax,
    pub supsubscription: SclServiceWithMax,
    pub confsigref: SclServiceWithMax,

    pub reportsettings: SclReportsettings,
}

/************************************************************************/
/*			2 scl 相关结构体 end					*/
/************************************************************************/

/************************************************************************/
/*			3 解析相关细节结构体 及函数 start					*/
/************************************************************************/
pub fn scl_services_init(scl_services: &mut SclServices) {
    /*NOTE: This memset initializes all boolean members to 0 (SD_FALSE).	*/
    // memset (scl_services, 0, sizeof (SCL_SERVICES));
    *scl_services = SclServices::default();
    //     let fix=b"Fix";
    //    for i in 0..3{
    //     scl_services.ReportSettings.cbName[i]=fix[i];
    //     scl_services.ReportSettings.datSet[i]=fix[i];
    //     scl_services.ReportSettings.rptID[i]=fix[i];
    //     scl_services.ReportSettings.optFields[i]=fix[i];
    //     scl_services.ReportSettings.bufTime[i]=fix[i];
    //     scl_services.ReportSettings.trgOps[i]=fix[i];
    //     scl_services.ReportSettings.intgPd[i]=fix[i];
    //    }
    scl_services.reportsettings.cbname = String::from("Fix");
    scl_services.reportsettings.datset = String::from("Fix");
    scl_services.reportsettings.rptid = String::from("Fix");
    scl_services.reportsettings.optfields = String::from("Fix");
    scl_services.reportsettings.buftime = String::from("Fix");
    scl_services.reportsettings.trgops = String::from("Fix");
    scl_services.reportsettings.intgpd = String::from("Fix");
}

pub fn _scl_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //println!("scl start *****************");
        if sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition != 0 {
            if sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition == 1
                || sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition == 2
            {
                sxdecctrl.scl_dec_ctrl.sclinfo.edition =
                    sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition;
                println!(
                    "'forceEdition' option used. Assuming 61850 Edition = {}",
                    sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition
                );
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.edition = 1;
                println!(
                    "Option forceEdition = {} not supported. Assuming 61850 Edition 1",
                    sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition
                );
            }
        } else {
            /* Look for attributes "version" & "revision", required in Ed 2, not present in Ed 1.*/
            let op_ver = sxdecctrl.scl_get_attr_ptr("version", SCL_ATTR_OPTIONAL);
            let op_rver = sxdecctrl.scl_get_attr_ptr("revision", SCL_ATTR_OPTIONAL);

            if op_rver.is_some() && op_ver.is_some() {
                sxdecctrl.scl_dec_ctrl.sclinfo.edition = 2;
                if let Some(version) = op_ver {
                    if !check_eq_2bs(version.as_bytes(), "2007".as_bytes()) {
                        println! ("Invalid SCL version = {}. Should be '2007' Assuming 61850 Edition 2 anyway.", version);
                    }
                }
                if let Some(revision) = op_rver {
                    if !check_eq_2bs(revision.as_bytes(), "A".as_bytes()) {
                        println! ("Invalid SCL revision = {}. Should be 'A'. Assuming 61850 Edition 2 anyway.", revision);
                    }
                }
            } else {
                println!("use default edith 1");
                sxdecctrl.scl_dec_ctrl.sclinfo.edition = 1;
            }
        }
        let scl_sub_tb_index_vec = vec![1, 2, 3, 4];
        sxdecctrl.sx_push(scl_sub_tb_index_vec);
    } else {
        //println!("scl end *****************");
        while sxdecctrl.items.len() > 0 {
            sxdecctrl.sx_pop();
        }
    }
}

pub fn _header_sfun(sxdecctrl: &mut IcdParseContext2) {
    /* Get required attributes	*/
    //println!("handle head ");
    let op_id = sxdecctrl.scl_get_attr_ptr("id", SCL_ATTR_REQUIRED);
    if let Some(id) = op_id {
        if id.as_bytes().len() > MAX_IDENT_LEN {
            return;
        }
        //println!("head id {}",id);
        sxdecctrl.scl_dec_ctrl.sclinfo.header.id = id;
    } else {
        return; /* At least one required attr not found. Stop now.	*/
    }

    let op_namestructure = sxdecctrl.scl_get_attr_ptr("nameStructure", SCL_ATTR_OPTIONAL);
    if let Some(namestructure) = op_namestructure {
        if !check_eq_2bs(namestructure.as_bytes(), "IEDName".as_bytes()) {
            println!("Header attribute nameStructure={} not allowed. Assuming nameStructure='IEDName' (i.e. 'Product Naming')", namestructure);
        }
    }
    /* Always assume nameStructure="IEDName" (i.e. "Product Naming")	*/
    sxdecctrl.scl_dec_ctrl.sclinfo.header.namestructure = SCL_NAMESTRUCTURE_IEDNAME;
}

pub fn _communication_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //CommunicationElements
        sxdecctrl.sx_push(vec![5]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _ied_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut match_found = false; /* set if IED name matches expected*/
    //let mut required = false;

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* start required attributes */
        let required = true;
        let op_name = sxdecctrl.scl_get_attr_ptr("name", required);
        if let Some(name) = op_name {
            if !chk_mms_ident_legal(&name) {
                println!("Illegal character in IED name {}'", name);
                sxdecctrl.errcode = SX_USER_ERROR;
                sxdecctrl.termflag = true;
                return;
            }
            /* Save to sclDecCtrl->iedNameProc to use while processing this IED.*/
            // for (i,c) in name.as_bytes().iter().enumerate(){
            //     sxdecctrl.scl_dec_ctrl.iedNameProc[i]=*c;
            //     if i>= (MAX_IDENT_LEN-1) {
            //         break;
            //     }
            // }
            sxdecctrl.scl_dec_ctrl.iednameproc = name.clone();

            /* SCL_PARSE_MODE_CID (default parse mode)	*/
            if check_eq_2bs(name.as_bytes(), sxdecctrl.scl_dec_ctrl.iedname.as_bytes()) {
                match_found = true;
            }
        } else {
            println!("requeid tag  header-name  not find");
            sxdecctrl.errcode = SX_USER_ERROR;
            sxdecctrl.termflag = true;
            return;
        }
        println!("ied found ?{}", match_found);

        if match_found {
            /* Initialize all default values in sclDecCtrl->scl_services.*/
            /* NOTE: Parsed values will be saved there. Later when SCL_SERVER	*/
            /* is allocated (see scl_server_add), this struct is copied there.*/
            scl_services_init(&mut sxdecctrl.scl_dec_ctrl.scl_services);

            // println!("SCL PARSE: IED 'name' match found: {}", name);
            sxdecctrl.scl_dec_ctrl.iednamematched = true;
            sxdecctrl.sx_push(vec![6, 7]);
            //IEDElements
        } else {
            println!("SCL PARSE: IED 'name' found  , not a match");
        }
    /* end required attributes */
    } else {
        sxdecctrl.scl_dec_ctrl.iednameproc = String::new(); /* clear iedName. Done with this IED.*/
        if sxdecctrl.scl_dec_ctrl.iednamematched == true {
            sxdecctrl.scl_dec_ctrl.iednamematched = false;
            sxdecctrl.sx_pop();
        }
    }
}

fn _datatypetemplates_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //DataTypeTemplatesElements
        sxdecctrl.sx_push(vec![8, 9, 10, 11]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _subnetwork_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_subnet = SclSubnet::default();
        /* Get required attributes.	*/
        let op_name = sxdecctrl.scl_get_attr_ptr("name", SCL_ATTR_REQUIRED);
        if let Some(name) = op_name {
            scl_subnet.name = name;
        } else {
            return;
        }
        let op_desc = sxdecctrl.scl_get_attr_ptr("desc", SCL_ATTR_OPTIONAL);
        if let Some(desc) = op_desc {
            scl_subnet.desc = desc;
        }

        let op_type = sxdecctrl.scl_get_attr_ptr("type", SCL_ATTR_OPTIONAL);
        if let Some(rtype) = op_type {
            scl_subnet.rtype = rtype;
            // println!("sub network att name {}",scl_subnet.r#type);
        }
        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.push(scl_subnet);
        //SubNetworkElements
        sxdecctrl.sx_push(vec![12]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _connectedap_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_cap = SclCap::default();
        /* Get required attributes	*/
        let op_iedname = sxdecctrl.scl_get_attr_ptr("iedName", SCL_ATTR_REQUIRED);
        if let Some(iedname) = op_iedname {
            scl_cap.iedname = iedname;
            //println!("ied name  att {}",scl_cap.iedName);
        } else {
            return;
        }

        let op_apname = sxdecctrl.scl_get_attr_ptr("apName", SCL_ATTR_REQUIRED);
        if let Some(apname) = op_apname {
            scl_cap.apname = apname;
            //println!("ied name  apName {}",scl_cap.apName);
        } else {
            return;
        }

        /* Get optional attributes.	*/
        let op_desc = sxdecctrl.scl_get_attr_ptr("desc", SCL_ATTR_OPTIONAL);
        if let Some(desc) = op_desc {
            scl_cap.desc = desc;
        }
        let len = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        if len > 0 {
            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[len - 1]
                .cap_vec
                .push(scl_cap);
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        //ConnectedAPElements
        sxdecctrl.sx_push(vec![13, 14, 15]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _address_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Only one Address allowed, so no need to alloc struct & add to list.*/
        /* Functions will save address info directly to this struct:	*/
        /*   "sclDecCtrl->sclInfo->subnet_vec->cap_vec->address".		*/
        //AddressElements
        sxdecctrl.sx_push(vec![16]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _address_p_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_END {
        /* Save this Address element to appropriate member of this structure.*/
        //get last subnethead index
        //get last caphead index
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        let op_type = sxdecctrl.scl_get_attr_ptr("type", SCL_ATTR_REQUIRED);
        if let Some(rtype) = op_type {
            if check_eq_2str_incaseinse(rtype.as_str(), "OSI-PSEL") {
                /* Set "psel" and "psel_len".	*/
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(psel) = utils::ascii_to_hex(txt) {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .psel_len = psel.len() as u32;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .psel = psel;
                    } else {
                        println!("Illegal OSI-PSEL ");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-SSEL") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(res) = utils::ascii_to_hex(txt) {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ssel_len = res.len() as u32;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ssel = res;
                    } else {
                        println!("Illegal OSI-SSEL ");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-TSEL") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(res) = utils::ascii_to_hex(txt) {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .tsel_len = res.len() as u32;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .tsel = res;
                    } else {
                        println!("Illegal OSI-TSEL ");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "IP") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    let res_ip: Result<Ipv4Addr, _> = txt.parse();
                    if let Ok(ip) = res_ip {
                        //println!("get ip {:?}",ip);
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ip = ip;
                    } else {
                        println!("err ip add");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-AP-Title") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(objid) = asciitoobjid(txt.as_str()) {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ap_title = objid;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ap_title_pres = true;
                    } else {
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-AE-Qualifier") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if txt.len() == 0 {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;

                        return;
                    }
                    let res_i32 = txt.trim().parse::<i32>();
                    if let Ok(res) = res_i32 {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ae_qual = res;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ae_qual_pres = true;
                    } else {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-AP-Invoke") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if txt.len() == 0 {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;

                        return;
                    }
                    let res_i32 = txt.trim().parse::<i32>();
                    if let Ok(res) = res_i32 {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ap_inv_id = res;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ap_inv_id_pres = true;
                    } else {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "OSI-AE-Invoke") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if txt.len() == 0 {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;

                        return;
                    }
                    let res_i32 = txt.trim().parse::<i32>();
                    if let Ok(res) = res_i32 {
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ae_inv_id = res;
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ae_title
                            .ae_inv_id_pres = true;
                    } else {
                        println!("Invalid AE-qual ,info len is zero");
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    println!("no content ,should not happen");
                    return;
                }
            }
        } else {
            return;
        }
    }
}

fn services_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* If optional "nameLength" attribute is present, ignore it.	*/
        /* NOTE: don't need to call an "add" function. Info will be saved in sclDecCtrl->scl_services.*/
        println!("SCL PARSE: Services section found");
        //ServicesElements
        sxdecctrl.sx_push(vec![
            60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
        ]);
    } else
    /* reason = SX_ELEMENT_END */
    {
        sxdecctrl.sx_pop();
    }
}

fn _accesspoint_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    let mut match_found = false;
    let mut apname = String::new();

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* start required attributes */
        required = true;
        if let Some(ref name) = sxdecctrl.scl_get_attr_ptr("name", required) {
            /* SCL_PARSE_MODE_CID (default parse mode)	*/
            if check_eq_2bs(
                name.trim().as_bytes(),
                sxdecctrl.scl_dec_ctrl.accesspointname.as_bytes(),
            ) {
                apname = name.clone();
                match_found = true;
            }
        } else {
            return;
        }

        /* Behavior depends on "parseMode".	*/

        if match_found {
            /* found caller structure with matching iedName/apName	*/
            let mut scl_server = SclServer::default();
            /* Add server now.	*/
            scl_server.iedname = sxdecctrl.scl_dec_ctrl.iednameproc.clone();
            scl_server.apname = apname.clone();

            /* CRITICAL: copy info from "Services" section saved in sclDecCtrl.	*/
            /* This should copy entire structure.	*/
            scl_server.scl_services = sxdecctrl.scl_dec_ctrl.scl_services.clone();
            println!("SCL PARSE: AccessPoint 'name' match found: {}", apname);
            sxdecctrl.scl_dec_ctrl.accesspointfound = true; /*NOTE: only get here if IED also found*/
            sxdecctrl.scl_dec_ctrl.accesspointmatched = true;

            sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.push(scl_server);

            //AccessPointElements
            sxdecctrl.sx_push(vec![23]);
        } else {
            println!(
                "SCL PARSE: AccessAccessPoint 'name' found {}, not a match",
                apname
            );
        }
    /* end required attributes */
    } else {
        /* SX_ELEMENT_END	*/
        if sxdecctrl.scl_dec_ctrl.accesspointmatched == true {
            sxdecctrl.scl_dec_ctrl.accesspointmatched = false;
            sxdecctrl.sx_pop();
        }
    }
}
fn _lnodetype_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    //SCL_LNTYPE *scl_lntype;

    let mut iedtype = String::new(); //[MAX_IDENT_LEN+1];	/* optional iedType attr, if found*/
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Assume iedType matched. Clear this below if match not found.	*/
        sxdecctrl.scl_dec_ctrl.iedtypematched = true;

        /* IMPORTANT: For "SCD" parse mode, check the optional iedType,	*/
        /*            if present, BEFORE saving anything.			*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("iedType", required) {
            if txt.trim().len() > 0 {
                iedtype = txt.trim().to_string();
            }
        }
        let mut scl_lntype = SclLntype::default();

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("id", required) {
            scl_lntype.id = txt.trim().to_string();
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("lnClass", required) {
            scl_lntype.lnclass = txt.trim().to_string();
        } else {
            return;
        }
        //println!("lntype {:?}", scl_lntype);
        sxdecctrl.scl_dec_ctrl.sclinfo.lntype_vec.push(scl_lntype);
        /* end required attributes */
        //LNodeTypeElements
        sxdecctrl.sx_push(vec![53]);
    } else {
        if sxdecctrl.scl_dec_ctrl.iedtypematched {
            sxdecctrl.sx_pop();
        }
    }
}
fn _dotype_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut iedtype = String::new(); //[MAX_IDENT_LEN+1];	/* optional iedType attr, if found*/
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Assume iedType matched. Clear this below if match not found.	*/
        sxdecctrl.scl_dec_ctrl.iedtypematched = true;

        /* IMPORTANT: For "SCD" parse mode, check the optional iedType,	*/
        /*            if present, BEFORE saving anything.			*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("iedType", required) {
            iedtype = txt.trim().to_string();
        }
        let mut scl_dotype = SclDotype::default();

        /* start required attributes */
        required = true;

        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("id", required) {
            scl_dotype.id = txt.trim().to_string();
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("cdc", required) {
            scl_dotype.cdc = txt.trim().to_string();
        } else {
            return;
        }
        /* end required attributes */
        //println!("dotype {:?}", scl_dotype);
        sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec.push(scl_dotype);
        //DOTypeElements
        sxdecctrl.sx_push(vec![54, 55]);
    } else {
        if sxdecctrl.scl_dec_ctrl.iedtypematched {
            sxdecctrl.sx_pop();
        }
    }
}

fn _datype_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    //ST_CHAR iedType[MAX_IDENT_LEN+1];	/* optional iedType attr, if found*/
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Assume iedType matched. Clear this below if match not found.	*/
        sxdecctrl.scl_dec_ctrl.iedtypematched = true;

        /* IMPORTANT: For "SCD" parse mode, check the optional iedType,	*/
        /*            if present, BEFORE saving anything.			*/
        // ret = scl_get_attr_copy (sxdecctrl, "iedType", iedType, (sizeof(iedType)-1), required);
        // if (ret == SD_SUCCESS && iedType[0] != '\0')	/* iedType is not empty string	*/
        //   {
        //   if (sclDecCtrl->parseMode == SCL_PARSE_MODE_SCD_FILTERED)
        //     {
        //     /* "SCD" parse mode AND "iedType" is present. Check for match.*/
        //     if (!scl_iedtype_match (scl_info, iedType))
        //       {	/* iedType DOES NOT match one requested	*/
        //       SXLOG_DEC1 ("DAType ignored: iedType='%s' is not in list passed to parser", iedType);
        //       sclDecCtrl->iedTypeMatched = SD_FALSE;	/* IGNORE THIS TYPE.	*/
        //       return;
        //       }
        //     }
        //   }
        let mut scl_datype = SclDatype::default();

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("id", required) {
            scl_datype.id = txt.trim().to_string();
        } else {
            return;
        }

        /* end required attributes */
        //   println!("datyep {:?}", scl_datype);
        sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec.push(scl_datype);
        // DATypeElements  /
        sxdecctrl.sx_push(vec![57]);
    } else {
        if sxdecctrl.scl_dec_ctrl.iedtypematched {
            sxdecctrl.sx_pop();
        }
    }
}
fn _enumtype_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_enumtype = SclEnumtype::default();

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("id", required) {
            scl_enumtype.id = txt.trim().to_string();
        } else {
            return;
        }
        /* end required attributes */
        //println!("enum {:?}", scl_enumtype);
        sxdecctrl
            .scl_dec_ctrl
            .sclinfo
            .enumtype_vec
            .push(scl_enumtype);

        //EnumTypeElements
        sxdecctrl.sx_push(vec![59]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _gse_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //  println!("gse fffffffffff");
        /* NOTE: save ptr in sclDecCtrl->scl_gse to use later in parsing.	*/
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let mut scl_gse = SclGse::default();
        let op_ldinst = sxdecctrl.scl_get_attr_ptr("ldInst", SCL_ATTR_REQUIRED);
        if let Some(ldinst) = op_ldinst {
            //   println!("gse ldinst {}",ldInst);

            scl_gse.ldinst = ldinst;
        } else {
            return;
        }
        let op_cbname = sxdecctrl.scl_get_attr_ptr("cbName", SCL_ATTR_REQUIRED);
        if let Some(cbname) = op_cbname {
            // println!("gse cb {}",cbName);

            scl_gse.cbname = cbname;
        } else {
            return;
        }

        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec[res_caplen - 1]
            .gse_vec
            .push(scl_gse);

        //GSEElements
        sxdecctrl.sx_push(vec![17, 18, 19]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _smv_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* NOTE: save ptr in sclDecCtrl->scl_smv to use later in parsing.	*/
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let mut scl_smv = SclSmv::default();
        let op_ldinst = sxdecctrl.scl_get_attr_ptr("ldInst", SCL_ATTR_REQUIRED);
        if let Some(ldinst) = op_ldinst {
            //   println!("gse ldinst {}",ldInst);

            scl_smv.ldinst = ldinst;
        } else {
            return;
        }
        let op_cbname = sxdecctrl.scl_get_attr_ptr("cbName", SCL_ATTR_REQUIRED);
        if let Some(cbname) = op_cbname {
            // println!("gse cb {}",cbName);

            scl_smv.cbname = cbname;
        } else {
            return;
        }

        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec[res_caplen - 1]
            .smv_vec
            .push(scl_smv);
        //SMVElements
        sxdecctrl.sx_push(vec![21]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _gse_address_sefun(sxdecctrl: &mut IcdParseContext2) {
    //  println!("gse addrd fgggggggggggggg");
    if sxdecctrl.reason == SX_ELEMENT_START {
        //GSEAddressElements
        sxdecctrl.sx_push(vec![20]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _gse_mintime_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Check required attribute.	*/

        let op_unit = sxdecctrl.scl_get_attr_ptr("unit", SCL_ATTR_REQUIRED);
        if let Some(ref unit) = op_unit {
            // println!("gse cb {}",cbName);
            if unit.trim() != "s" {
                println!("unit={} not allowed. Assuming unit='s'.", unit);
            }
        } else {
            return;
        }

        /* Check optional attribute.	*/
        let op_mul = sxdecctrl.scl_get_attr_ptr("multiplier", SCL_ATTR_OPTIONAL);
        if let Some(ref mul) = op_mul {
            // println!("gse cb {}",cbName);
            if mul.trim() != "m" {
                println!("multiplier= {} not allowed. Assuming multiplier='m'.", mul);
            }
        }
    } else
    /* reason = SX_ELEMENT_END */
    {
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        let mut third_len = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
                let gselen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                    [res_caplen - 1]
                    .gse_vec
                    .len();
                if gselen > 0 {
                    third_len = gselen;
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        if let Some(ref txt) = sxdecctrl.op_entry_text {
            let res_x = txt.parse::<u32>();
            if let Ok(x) = res_x {
                sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec[res_caplen - 1]
                    .gse_vec[third_len - 1]
                    .mintime = x;
            } else {
                println!("gse mintime parse err");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
/************************************************************************/
/*			_GSE_MaxTime_SEFun				*/
/* Units must be "ms" but check "unit" and "multiplier" attributes.	*/
/************************************************************************/
fn _gse_maxtime_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let op_unit = sxdecctrl.scl_get_attr_ptr("unit", SCL_ATTR_REQUIRED);
        if let Some(ref unit) = op_unit {
            // println!("gse cb {}",cbName);
            if unit.trim() != "s" {
                println!("unit={} not allowed. Assuming unit='s'.", unit);
            }
        } else {
            return;
        }

        /* Check optional attribute.	*/
        let op_mul = sxdecctrl.scl_get_attr_ptr("multiplier", SCL_ATTR_OPTIONAL);
        if let Some(ref mul) = op_mul {
            // println!("gse cb {}",cbName);
            if mul.trim() != "m" {
                println!("multiplier= {} not allowed. Assuming multiplier='m'.", mul);
            }
        }
    } else
    /* reason = SX_ELEMENT_END */
    {
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        let mut third_len = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
                let gselen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                    [res_caplen - 1]
                    .gse_vec
                    .len();
                if gselen > 0 {
                    third_len = gselen;
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        if let Some(ref txt) = sxdecctrl.op_entry_text {
            let res_x = txt.parse::<u32>();
            if let Ok(x) = res_x {
                sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec[res_caplen - 1]
                    .gse_vec[third_len - 1]
                    .maxtime = x;
            } else {
                println!("gse mintime parse err");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _gse_address_p_sefun(sxdecctrl: &mut IcdParseContext2) {
    //println!("get address fdddddddddddddd");
    if sxdecctrl.reason == SX_ELEMENT_END {
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        let mut third_len = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
                let gselen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                    [res_caplen - 1]
                    .gse_vec
                    .len();
                if gselen > 0 {
                    third_len = gselen;
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        let op_type = sxdecctrl.scl_get_attr_ptr("type", SCL_ATTR_REQUIRED);
        if let Some(rtype) = op_type {
            if check_eq_2str_incaseinse(rtype.as_str(), "MAC-Address") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(mac) = mac_address::MacAddress::from_str(txt.as_str()) {
                        // println!("mac is {}",mac.clone());
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .gse_vec[third_len - 1]
                            .mac = mac;
                    } else {
                        println!("pare mac err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "APPID") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(appid) = u32::from_str_radix(txt.trim(), 16) {
                        if appid > 0xffff {
                            println!("pare appid err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            // println!("appid  is {}",appid);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .gse_vec[third_len - 1]
                                .appid = appid;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "VLAN-PRIORITY") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(vlanpri) = u32::from_str_radix(txt.trim(), 16) {
                        if vlanpri > 7 {
                            println!("pare VLANPRI err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            // println!("VLANPRI  is {}",VLANPRI);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .gse_vec[third_len - 1]
                                .vlanpri = vlanpri;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "VLAN-ID") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(vlanid) = u32::from_str_radix(txt.trim(), 16) {
                        if vlanid > 0xfff {
                            println!("pare VLANID err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            println!("VLANID  is {}", vlanid);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .gse_vec[third_len - 1]
                                .vlanid = vlanid;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            }
        } else {
            return;
        }
    }
}
fn _smv_address_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //SMVAddressElements
        sxdecctrl.sx_push(vec![22]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _smv_address_p_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_END {
        let sublen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec.len();
        let mut res_caplen = 0;
        let mut third_len = 0;
        if sublen > 0 {
            let caplen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1]
                .cap_vec
                .len();
            if caplen > 0 {
                res_caplen = caplen;
                let smvlen = sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                    [res_caplen - 1]
                    .smv_vec
                    .len();
                if smvlen > 0 {
                    third_len = smvlen;
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        let op_type = sxdecctrl.scl_get_attr_ptr("type", SCL_ATTR_REQUIRED);
        if let Some(rtype) = op_type {
            if check_eq_2str_incaseinse(rtype.as_str(), "MAC-Address") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(mac) = mac_address::MacAddress::from_str(txt.as_str()) {
                        //  println!("mac is {}",mac.clone());
                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .smv_vec[third_len - 1]
                            .mac = mac;
                    } else {
                        println!("pare mac err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "APPID") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(appid) = u32::from_str_radix(txt.trim(), 16) {
                        if appid > 0xffff {
                            println!("pare appid err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            //  println!("appid  is {}",appid);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .smv_vec[third_len - 1]
                                .appid = appid;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "VLAN-PRIORITY") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(vlanpri) = u32::from_str_radix(txt.trim(), 16) {
                        if vlanpri > 7 {
                            println!("pare VLANPRI err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            //  println!("VLANPRI  is {}",VLANPRI);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .smv_vec[third_len - 1]
                                .vlanpri = vlanpri;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else if check_eq_2str_incaseinse(rtype.as_str(), "VLAN-ID") {
                if let Some(ref txt) = sxdecctrl.op_entry_text {
                    if let Ok(vlanid) = u32::from_str_radix(txt.trim(), 16) {
                        if vlanid > 0xfff {
                            println!("pare VLANID err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            //println!("VLANID  is {}", VLANID);
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .smv_vec[third_len - 1]
                                .vlanid = vlanid;
                        }
                    } else {
                        println!("pare appid err {}", txt);
                        sxdecctrl.errcode = SX_USER_ERROR;
                        return;
                    }
                } else {
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            }
        } else {
            return;
        }
    }
}
fn _server_sefun(sxdecctrl: &mut IcdParseContext2) {
    //println!("server fun exceeds");
    if sxdecctrl.reason == SX_ELEMENT_START {
        //ServerElements
        sxdecctrl.sx_push(vec![24]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _ldevice_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    if sxdecctrl.reason == SX_ELEMENT_START {
        let sever_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if sever_len > 0 {
            /* start optional attributes */

            let mut scl_ld = SclLd::default();
            if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
                scl_ld.desc = txt.trim().to_string();
            }
            /* end optional attributes */

            /* start required attributes */
            required = true;
            if let Some(txt) = sxdecctrl.scl_get_attr_ptr("inst", required) {
                scl_ld.inst = txt.trim().to_string();

                if chk_mms_ident_legal(&scl_ld.inst) {
                    println!("scl ld {} {}", scl_ld.inst, scl_ld.desc);
                    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[sever_len - 1]
                        .ld_vec
                        .push(scl_ld);
                    //LDeviceElements
                    sxdecctrl.sx_push(vec![25, 26]);
                } else {
                    println!("Illegal character in LDevice inst {}", scl_ld.inst);
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                return;
            }

        /* end required attributes */
        } else {
            println!("scl_ld add empty server ,should not happen");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        /* reason == SX_ELEMENT_END	*/

        let sever_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        let mut ld_len = 0;
        if sever_len > 0 {
            ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[sever_len - 1]
                .ld_vec
                .len();
            if ld_len > 0 {
                let mut name = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[sever_len - 1]
                    .iedname
                    .clone();
                name += &(sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[sever_len - 1].ld_vec
                    [ld_len - 1]
                    .inst);

                if name.len() < MAX_IDENT_LEN {
                    // println!("end domnamie {}",name);
                    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[sever_len - 1].ld_vec[ld_len - 1]
                        .domname = name;
                    sxdecctrl.sx_pop();
                } else {
                    println!("Cannot create LD: constructed domain name too long");
                    sxdecctrl.errcode = SX_USER_ERROR;
                    return;
                }
            } else {
                println!("empty ld vec ,should not happen");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            println!("empty serer vec ,should not happen");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _ln_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut scl_ln = SclLn::default();
    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }

    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut required = false;
        let mut scl_ln = SclLn::default();

        /* start optional attributes */
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_ln.desc = txt.trim().to_string();
        }
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("prefix", required) {
            scl_ln.prefix = txt.trim().to_string();
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("lnType", required) {
            scl_ln.lntype = txt.trim().to_string();
        } else {
            return;
        }
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("inst", required) {
            scl_ln.inst = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_ln.inst) {
                println!("ileegal com name {} ", scl_ln.inst);
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            return;
        }
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("lnClass", required) {
            scl_ln.lnclass = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_ln.lnclass) {
                println!("ileegal com name {} ", scl_ln.lnclass);
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            return;
        }

        if let Some(ref tag) = sxdecctrl.op_start_tag {
            let tagname = tag.tag.trim();

            if check_eq_2str_incaseinse(tagname, "LN0")
                && !check_eq_2str_incaseinse(&scl_ln.lnclass, "LLN0")
            {
                sxdecctrl.errcode = SX_USER_ERROR;
                sxdecctrl.termflag = true;
                println! ("SCL PARSE: Attribute 'lnClass' of element 'LN0' has a value other then 'LLN0' (schema violation).");
                return;
            }
            // println!("ln class:{} inst {} prefix {} desc {} type {}",scl_ln.lnClass,scl_ln.inst,scl_ln.prefix,scl_ln.desc,scl_ln.lnType);

            sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                .ln_vec
                .push(scl_ln);
            if check_eq_2str_incaseinse(tagname, "LN0") {
                //LN0Elements
                sxdecctrl.sx_push(vec![27, 28, 29, 30, 31, 32, 33, 34]);
            } else {
                //LNElements
                sxdecctrl.sx_push(vec![35, 36, 37, 38, 39, 40]);
            }
        /* end required attributes */
        } else {
            println!(" no tag ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        /* reason == SX_ELEMENT_END	*/
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            //println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        /* Construct MMS Variable name from scl info.	*/
        println!("ln len {}", ln_len);
        if sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .lnclass
            .len()
            != 4
        {
            println!(
                "Illegal lnClass='{}'. Must be exactly 4 char",
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                    [ln_len - 1]
                    .lnclass
            );
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        } else if (sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec[ln_len - 1]
            .prefix
            .len()
            + sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                [ln_len - 1]
                .inst
                .len())
            > 11
        {
            println!(
                "Illegal definition for lnClass='{}': prefix ({}) plus inst (%s) > 11 char.",
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                    [ln_len - 1]
                    .prefix,
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                    [ln_len - 1]
                    .inst
            );

            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        } else {
            let mut name = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec
                [ld_len - 1]
                .ln_vec[ln_len - 1]
                .prefix
                .clone();
            name += &sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                .ln_vec[ln_len - 1]
                .lnclass;
            name += &sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                .ln_vec[ln_len - 1]
                .inst;
            if name.len() > MAX_IDENT_LEN {
                //  println!("name len too long ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            } else {
                // println!("var name  {} ", name);
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                    .ln_vec[ln_len - 1]
                    .varname = name;
            }
        }

        sxdecctrl.sx_pop();
    }
}

fn _dataset_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_dataset = SclDataset::default();

        /* start optional attributes */
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_dataset.desc = txt;
        }
        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            scl_dataset.name = txt.trim().to_owned();
            if !chk_mms_ident_legal(&scl_dataset.name) {
                println!("dataset name not valid  {}", txt);
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
            /* end required attributes */
            let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
            if servr_len == 0 {
                println!("serve len empyt ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
            let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
                .ld_vec
                .len();
            if ld_len == 0 {
                println!("ld len empyt ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
            let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec
                [ld_len - 1]
                .ln_vec
                .len();
            if ln_len == 0 {
                println!("ln len empyt ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
            // println!("dataset {} {}",scl_dataset.name,scl_dataset.desc);
            sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                [ln_len - 1]
                .dataset_vec
                .push(scl_dataset);
            //DataSetElements
            sxdecctrl.sx_push(vec![41]);
        } else {
            return;
        }
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _reportcontrol_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Alloc struct, save ptr in sclDecCtrl, & set local ptr to it.	*/
        let mut scl_rcb = SclRcb::default();

        /* start optional attributes */
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_rcb.desc = txt;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("datSet", required) {
            scl_rcb.datset = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("intgPd", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_rcb.intgpd = num;
            } else {
                println!("rcb inntpd parse faild  ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("bufTime", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_rcb.buftime = num;
            } else {
                println!("rcb bufTime parse faild  ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("buffered", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_rcb.buffered = true;
            } else {
                scl_rcb.buffered = false;
            }
        }
        /* NOTE: we only accept default value of indexed="true".	*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("indexed", required) {
            if check_eq_2str_incaseinse(txt.trim(), "false") {
                println!("rcb  indexed should defaut tobe true");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        }

        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("rptID", required) {
            scl_rcb.rptid = txt.trim().to_string();
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            scl_rcb.name = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_rcb.name) {
                println!("rcb  name att name not valid");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
            /* end required attributes */
        } else {
            return;
        }

        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("confRev", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_rcb.confrev = num;
            } else {
                println!("rcb confRev parse faild  ");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            return;
        }
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        //  println!("rcb {:?}  ", scl_rcb);
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .rcb_vec
            .push(scl_rcb);

        //ReportControlElements
        sxdecctrl.sx_push(vec![42, 43, 44]);
    } else
    /* reason = SX_ELEMENT_END */
    {
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let rcb_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec[ln_len - 1]
            .rcb_vec
            .len();
        if rcb_len == 0 {
            println!("rcb len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        /* CRITICAL: Copy TrgOps to scl_rcb.	*/
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .rcb_vec[rcb_len - 1]
            .trgops = sxdecctrl.scl_dec_ctrl.trgops;

        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .rcb_vec[rcb_len - 1]
            .optflds = sxdecctrl.scl_dec_ctrl.rcb_sub_data.rcb_optflds;

        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .rcb_vec[rcb_len - 1]
            .maxclient = sxdecctrl.scl_dec_ctrl.rcb_sub_data.max;
        /* If "RptEnabled max" not configured, set default value*/
        if sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .rcb_vec[rcb_len - 1]
            .maxclient
            == 0
        {
            sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                [ln_len - 1]
                .rcb_vec[rcb_len - 1]
                .maxclient = 1;
        }
        // println!(
        //     "end rcb {:?}",
        //     sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        //         [ln_len - 1]
        //         .rcb_vec[rcb_len - 1]
        // );
        /* default	*/
        /* NOTE: scl_rcb is all filled in now	*/
        sxdecctrl.sx_pop();
    }
}

fn _doi_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    let mut ix = String::new();
    let mut name = String::new();

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* start optional attributes */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ix", required) {
            if txt.trim().len() > 0 {
                ix = txt.trim().to_string();
            }
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            if txt.trim().len() > 0 {
                name = txt.trim().to_string();
            }
        } else {
            return;
        }

        /* end required attributes */

        /* Start creation of flattened name */
        sxdecctrl.scl_dec_ctrl.flattened = String::new(); /* CRITICAL: start with empty flatname*/
        if let Err(e) = construct_flattened(
            &mut sxdecctrl.scl_dec_ctrl.flattened,
            MAX_FLAT_LEN,
            &name,
            &ix,
        ) {
            /* error already logged.	*/
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("flat name contru falied ");
            println!("err {}", e);
            return;
        }

        // println!(
        //     "SCL PARSE: Created flattened variable: '{}'",
        //     sxdecctrl.scl_dec_ctrl.flattened
        // );
        //DOIElements
        sxdecctrl.sx_push(vec![48, 49]);
    } else {
        sxdecctrl.sx_pop();
    }
}
/************************************************************************/
/*			_SampledValueControl_SEFun			*/
/* DEBUG: if parser called separate start and end functions, the lower	*/
/*   functs could be called directly & this funct would not be needed.	*/
/************************************************************************/
fn _sampledvaluecontrol_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        _sampledvaluecontrol_sfun(sxdecctrl);
    } else {
        _sampledvaluecontrol_efun(sxdecctrl);
    }
}

/************************************************************************/
/*			_SampledValueControl_SFun			*/
/* Handle Start tag							*/
/************************************************************************/
fn _sampledvaluecontrol_sfun(sxdecctrl: &mut IcdParseContext2) {
    /* Alloc struct, save in sclDecCtrl, & set local ptr to it.	*/
    let mut scl_svcb = SclSvcb::default();
    /* start required attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", SCL_ATTR_REQUIRED) {
        scl_svcb.name = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("smvID", SCL_ATTR_REQUIRED) {
        scl_svcb.smvid = txt.trim().to_string();
        if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2 {
            if scl_svcb.name.len() > MVL61850_MAX_OBJREF_LEN {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("svcb name len toolong");
                return;
            }
        } else {
            if scl_svcb.name.len() > MVL61850_MAX_RPTID_LEN {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("svcb name len toolong");
                return;
            }
        }

        if !chk_comp_name_legal(&scl_svcb.name) {
            println!(
                "Illegal character in SampledValueControl name '{}'",
                scl_svcb.name
            );
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("smpRate", SCL_ATTR_REQUIRED) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_svcb.smprate = num;
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("svcb smpRate parse err");
            return;
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("nofASDU", SCL_ATTR_REQUIRED) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_svcb.nofasdu = num;
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("svcb nofASDU parse err");
            return;
        }
    }

    /* end required attributes */

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", SCL_ATTR_OPTIONAL) {
        scl_svcb.desc = txt.to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("datSet", SCL_ATTR_OPTIONAL) {
        scl_svcb.datset = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("confRev", SCL_ATTR_OPTIONAL) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_svcb.confrev = num;
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("svcb confRev parse err");
            return;
        }
    }
    scl_svcb.multicast = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("multicast", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "false") {
            scl_svcb.multicast = false;
        }
    }

    /* "smpMod" is for Edition 2 only. Should never be found in Edition 1 SCL file.*/
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("smpMod", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "SmpPerPeriod") {
            scl_svcb.smpmod = 0;
        } else if check_eq_2str_incaseinse(txt.trim(), "SmpPerSec") {
            scl_svcb.smpmod = 1;
        } else if check_eq_2str_incaseinse(txt.trim(), "SecPerSmp") {
            scl_svcb.smpmod = 2;
        } else {
            println!(
                "smpMod='{}' is not allowed. Using default value 'SmpPerPeriod' (0)",
                txt
            );
        }
    }
    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    //  println!("rcb {:?}  ", scl_rcb);
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec[ln_len - 1]
        .svcb_vec
        .push(scl_svcb);
    /* end optional attributes */
    //SampledValueControlElements
    sxdecctrl.sx_push(vec![46]);
}
/************************************************************************/
/*			_SampledValueControl_EFun			*/
/* Handle End tag							*/
/************************************************************************/
fn _sampledvaluecontrol_efun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.sx_pop();
}
fn _logcontrol_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_lcb = SclLcb::default();

        /* start optional attributes */
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_lcb.desc = txt;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("intgPd", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_lcb.intgpd = num;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("lcb intpd pare eer");
                return;
            }
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("datSet", required) {
            scl_lcb.datset = txt.trim().to_string();
        }
        scl_lcb.logena = false; /* default */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("logEna", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_lcb.logena = true;
            }
        }

        scl_lcb.reasoncode = false; /* default */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("reasonCode", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_lcb.reasoncode = true;
            }
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            scl_lcb.name = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_lcb.name) {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("lcb name invalid eer  {}", scl_lcb.name);
                return;
            }
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("logName", required) {
            scl_lcb.logname = txt.trim().to_string();
        } else {
            return;
        }
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .lcb_vec
            .push(scl_lcb);
        /* If required attributes parsed OK, make sure "name" is legal.*/

        /* end required attributes */
        //LogControlElements
        sxdecctrl.sx_push(vec![45]);
    } else
    /* reason = SX_ELEMENT_END */
    {
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let lcb_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec[ln_len - 1]
            .lcb_vec
            .len();
        if lcb_len == 0 {
            println!("lcb len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        /* CRITICAL: Copy TrgOps to scl_lcb.	*/
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .lcb_vec[lcb_len - 1]
            .trgops = sxdecctrl.scl_dec_ctrl.trgops;
        // println!( " this lcb is {:?}",   sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        // [ln_len - 1]
        // .lcb_vec[lcb_len - 1]);
        /* NOTE: scl_lcb is all filled in now	*/
        sxdecctrl.sx_pop();
    }
}
fn _settingcontrol_sfun(sxdecctrl: &mut IcdParseContext2) {
    /* start optional attributes */
    let mut required = false;
    let mut scl_sgcb = SclSgcb::default();
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
        scl_sgcb.desc = txt.to_string();
    }
    scl_sgcb.actsg = 1; /* default value */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("actSG", required) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_sgcb.actsg = num;
        }
    }
    /* end optional attributes */

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("numOfSGs", required) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_sgcb.numofsgs = num;
        }
    } else {
        return;
    }
    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    // println!("sgcb {:?}", scl_sgcb);
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .sgcb = Box::new(scl_sgcb);
    /* end required attributes */
}

fn _gsecontrol_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut scl_gcb = SclGcb::default();

    /* start optional attributes */
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
        scl_gcb.desc = txt;
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("confRev", required) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_gcb.confrev = num;
        } else {
            println!("gcb confrev parse err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("datSet", required) {
        scl_gcb.datset = txt.trim().to_owned();
    }
    scl_gcb.isgoose = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
        if check_eq_2str_incaseinse(txt.trim(), "GSSE") {
            scl_gcb.isgoose = false;
        }
    }

    /* end optional attributes */

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
        scl_gcb.name = txt.trim().to_string();
        if !chk_comp_name_legal(&scl_gcb.name) {
            println!("Illegal character in GSEControl name '{}'", scl_gcb.name);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("appID", required) {
        scl_gcb.appid = txt.to_string();
    } else {
        return;
    }

    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    // println!("gcb {:?}", scl_gcb);
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec[ln_len - 1]
        .gcb_vec
        .push(scl_gcb);

    /* end required attributes */
}

fn _inputs_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //InputsElements
        sxdecctrl.sx_push(vec![47]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _fcda_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ds_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .dataset_vec
        .len();
    if ds_len == 0 {
        println!("ds len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }

    let mut scl_fcda = SclFcda::default();

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ldInst", required) {
        scl_fcda.ldinst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("prefix", required) {
        scl_fcda.prefix = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("lnInst", required) {
        scl_fcda.lninst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("lnClass", required) {
        scl_fcda.lnclass = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("doName", required) {
        scl_fcda.doname = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("daName", required) {
        scl_fcda.daname = txt.trim().to_string();
    }
    /* NOTE: "ix" should be present only in Edition 2 SCL files.	*/
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ix", required) {
        scl_fcda.ix = txt.trim().to_string();
    }
    /* end optional attributes */

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("fc", required) {
        scl_fcda.fc = txt.trim().to_string();
    } else {
        return;
    }

    /* end required attributes */

    /* Construct domain name from SCL info	*/
    /* ASSUME nameStructure="IEDName" (domain name = IED name + LDevice inst)*/
    /* nameStructure="FuncName" is OBSOLETE.				*/

    let iedname_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .iedname
        .len();
    let ldinst_len = scl_fcda.ldinst.len();
    if iedname_len + ldinst_len <= MAX_IDENT_LEN {
        let mut name = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .iedname
            .clone();
        name += &scl_fcda.ldinst;
        // println!("ldinst {} prefix {} lninst {} lnclss {}  doname {} daname {}  fc {}",
        // scl_fcda.ldInst, scl_fcda.prefix, scl_fcda.lnInst,scl_fcda.lnClass, scl_fcda.doName,scl_fcda.daName,scl_fcda.fc);
        // println!("fcda domname {}", name);
        scl_fcda.domname = name;
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .dataset_vec[ds_len - 1]
            .fcda_vec
            .push(scl_fcda);
    } else {
        println!("fcda name too long ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
}
fn _trgops_sfun(sxdecctrl: &mut IcdParseContext2) {
    // println!("now tripgs ");
    let required = false;

    sxdecctrl.scl_dec_ctrl.trgops = 0; /* Start with all bits=0	*/

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dchg", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(
                &mut [sxdecctrl.scl_dec_ctrl.trgops],
                TRGOPS_BITNUM_DATA_CHANGE,
            );
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("qchg", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(
                &mut [sxdecctrl.scl_dec_ctrl.trgops],
                TRGOPS_BITNUM_QUALITY_CHANGE,
            );
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dupd", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(
                &mut [sxdecctrl.scl_dec_ctrl.trgops],
                TRGOPS_BITNUM_DATA_UPDATE,
            );
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("period", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(
                &mut [sxdecctrl.scl_dec_ctrl.trgops],
                TRGOPS_BITNUM_INTEGRITY,
            );
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("gi", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(
                &mut [sxdecctrl.scl_dec_ctrl.trgops],
                TRGOPS_BITNUM_GENERAL_INTERROGATION,
            );
        }
    } else {
        utils::bstr_bit_set_on(
            &mut [sxdecctrl.scl_dec_ctrl.trgops],
            TRGOPS_BITNUM_GENERAL_INTERROGATION,
        );
    }

    /* NOTE: "gi" defaults to "true".	*/

    /* end optional attributes */
}

fn _optflds_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut optflds: [u8; 2] = [0; 2];

    /* start optional attributes */

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("seqNum", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_SQNUM);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("timeStamp", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_TIMESTAMP);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataSet", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_DATSETNAME);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("reasonCode", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_REASON);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataRef", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_DATAREF);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("bufOvfl", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_BUFOVFL);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("entryID", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_ENTRYID);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("configRef", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_CONFREV);
        }
    }

    sxdecctrl.scl_dec_ctrl.rcb_sub_data.rcb_optflds = optflds;

    /* end optional attributes */
}

fn _rptenabled_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut max = 1;

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_OPTIONAL) {
        if let Ok(num) = txt.parse::<u32>() {
            if num == 0 || num > 99 {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("rcb max att num  invalid {} ", num);
                return;
            }
            max = num;
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("rcb max att num  invalid2 ");
            return;
        }
    }
    sxdecctrl.scl_dec_ctrl.rcb_sub_data.max = max;
}
fn _smvopts_sfun(sxdecctrl: &mut IcdParseContext2) {
    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let smv_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec[ln_len - 1]
        .svcb_vec
        .len();
    if smv_len == 0 {
        println!("smv len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }

    let mut optflds: u8 = 0;
    let mut securitypres = false;
    let mut datarefpres = false;

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sampleRate", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_SMPRATE);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("refreshTime", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_REFRTM);
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sampleSynchronized", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_SMPSYNCH);
        }
    }

    /* "sampleSynchronized" must be "true" for Edition 2.	*/
    if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2
        && !utils::bstr_bit_get(&mut [optflds], SVOPT_BITNUM_SMPSYNCH)
    {
        println! ("sampleSynchronized='false' not allowed for Edition 2. Automatically setting it to 'true'.");
        utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_SMPSYNCH);
    }

    /* "dataSet" is for Edition 2 only.	*/
    if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2 {
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataSet", SCL_ATTR_OPTIONAL) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_DATSET);
            }
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("security", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            securitypres = true;
            if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2 {
                utils::bstr_bit_set_on(&mut [optflds], SVOPT_BITNUM_SECURITY);
            }
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataRef", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            datarefpres = true;
        }
    }
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .optflds = optflds;

    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .securitypres = securitypres;
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .datarefpres = datarefpres;
    // println!(
    //     "smv is {:?}",
    //     sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
    //         [ln_len - 1]
    //         .svcb_vec[smv_len - 1]
    // );

    /* NOTE: SCL calls this "dataRef", but 7-2 & 9-2 call it "DatSet".	*/
    /* For Edition 2, "dataRef" is not allowed. Should never be present.	*/
    /* Edition 2 uses SVOPT_BITNUM_DATSET instead (see "dataSet" attr above).*/
    /* scl_svcb calloced so init val is FALSE*/
    /* end optional attributes */
}
fn _extref_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut scl_extref = SclExtref::default();

    /* start optional attributes */
    /* "desc" and "intAddr" are allocated pointers. The rest are fixed buffers.*/
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", SCL_ATTR_OPTIONAL) {
        scl_extref.desc = txt.to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("intAddr", SCL_ATTR_OPTIONAL) {
        scl_extref.intaddr = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("iedName", SCL_ATTR_OPTIONAL) {
        scl_extref.iedname = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ldInst", SCL_ATTR_OPTIONAL) {
        scl_extref.ldinst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("prefix", SCL_ATTR_OPTIONAL) {
        scl_extref.prefix = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("lnClass", SCL_ATTR_OPTIONAL) {
        scl_extref.lnclass = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("lnInst", SCL_ATTR_OPTIONAL) {
        scl_extref.lninst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("doName", SCL_ATTR_OPTIONAL) {
        scl_extref.doname = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("daName", SCL_ATTR_OPTIONAL) {
        scl_extref.daname = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("serviceType", SCL_ATTR_OPTIONAL) {
        scl_extref.servicetype = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("srcLDInst", SCL_ATTR_OPTIONAL) {
        scl_extref.srcldinst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("srcPrefix", SCL_ATTR_OPTIONAL) {
        scl_extref.srcprefix = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("srcLNClass", SCL_ATTR_OPTIONAL) {
        scl_extref.srclnclass = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("srcLNInst", SCL_ATTR_OPTIONAL) {
        scl_extref.srclninst = txt.trim().to_string();
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("srcCBName", SCL_ATTR_OPTIONAL) {
        scl_extref.srccbname = txt.trim().to_string();
    }

    /* end optional attributes */
    let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
    if servr_len == 0 {
        println!("serve len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
        .ld_vec
        .len();
    if ld_len == 0 {
        println!("ld len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
        .ln_vec
        .len();
    if ln_len == 0 {
        println!("ln len empyt ");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec[ln_len - 1]
        .extref_vec
        .push(scl_extref);
}

fn _sdi_sefun(sxdecctrl: &mut IcdParseContext2) {
    //ST_CHAR *p;
    let mut required = false;
    let mut name = String::new();
    let mut ix = String::new();

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* start optional attributes */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ix", required) {
            if txt.trim().len() > 0 {
                ix = txt.trim().to_string();
            }
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            name = txt.trim().to_string();
        } else {
            return;
        }

        /* end required attributes */

        /* Continue creation of flattened name */
        if let Err(e) = construct_flattened(
            &mut sxdecctrl.scl_dec_ctrl.flattened,
            MAX_FLAT_LEN,
            &name,
            &ix,
        ) {
            /* error already logged.	*/
            println!("contruct failed  {}", e);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        // println!(
        //     "SCL PARSE: Appended to flattened variable: '{}'",
        //     sxdecctrl.scl_dec_ctrl.flattened
        // );
        // SDIElements
        sxdecctrl.sx_push(vec![50, 51]);
    } else
    /* reason = SX_ELEMENT_END */
    {
        /* Remove the last item from the flattened string */
        if let Some(index) = sxdecctrl.scl_dec_ctrl.flattened.rfind('$') {
            let (t1, _t2) = sxdecctrl.scl_dec_ctrl.flattened.split_at(index);
            let t3 = t1.to_string();
            sxdecctrl.scl_dec_ctrl.flattened = t3;
        }

        //  let temp=sxdecctrl.scl_dec_ctrl.flattened.trim_end_matches( |c| c == '$'  ).to_string();
        //  sxdecctrl.scl_dec_ctrl.flattened=temp;
        // p = strrchr(sclDecCtrl->flattened, '$');
        // if (p != NULL)
        //   *p = 0;
        // SXLOG_CDEC1 ("SCL PARSE: Removed last item from flattened variable: '%s'", sclDecCtrl->flattened);
        sxdecctrl.sx_pop();
    }
}

fn _dai_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    let mut name = String::new();
    let mut ix = String::new();

    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_dai = SclDai::default();

        /* start optional attributes */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ix", required) {
            ix = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sAddr", required) {
            scl_dai.saddr = txt.trim().to_string();
        }
        scl_dai.valkind = "Set".to_string();
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("valKind", required) {
            scl_dai.valkind = txt.trim().to_string();
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            name = txt.trim().to_string();
        } else {
            return;
        }
        /* end required attributes */

        /* Continue creation of flattened name */
        if let Err(e) = construct_flattened(
            &mut sxdecctrl.scl_dec_ctrl.flattened,
            MAX_FLAT_LEN,
            &name,
            &ix,
        ) {
            /* error already logged.	*/
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("construc err {}", e);
            return;
        }

        // println!(
        //     "SCL PARSE: Appended to flattened variable: '{}'",
        //     sxdecctrl.scl_dec_ctrl.flattened
        // );
        scl_dai.flattened = sxdecctrl.scl_dec_ctrl.flattened.clone();

        // scl_dai_add
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
            [ln_len - 1]
            .dai_vec
            .push(scl_dai);
        //DAIElements
        sxdecctrl.sx_push(vec![52]);
    } else
    /* reason = SX_ELEMENT_END */
    {
        /* Remove the last item from the flattened string */
        if let Some(index) = sxdecctrl.scl_dec_ctrl.flattened.rfind('$') {
            let (t1, _t2) = sxdecctrl.scl_dec_ctrl.flattened.split_at(index);
            let t3 = t1.to_string();
            sxdecctrl.scl_dec_ctrl.flattened = t3;
        }
        // p = strrchr(sclDecCtrl->flattened, '$');
        // if (p != NULL)
        //   *p = 0;
        // SXLOG_CDEC1 ("SCL PARSE: Removed last item from flattened variable: '%s'", sclDecCtrl->flattened);
        sxdecctrl.sx_pop();
    }
}

/************************************************************************/
/*			_DAI_Val_SEFun					*/
/* Sets "sclDecCtrl->scl_dai->Val" OR adds entry to the linked list	*/
/* "sclDecCtrl->scl_dai->sgval_vec".					*/
/* NOTE: sclDecCtrl->sGroupTmp is set when reason == SX_ELEMENT_START	*/
/*       and used when reason == SX_ELEMENT_END.			*/
/************************************************************************/

fn _dai_val_sefun(sxdecctrl: &mut IcdParseContext2) {
    //SCL_SG_VAL *scl_sg_val;

    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sGroup attr NOT present	*/
        /* start optional attributes (don't care about return)	*/

        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sGroup", SCL_ATTR_OPTIONAL) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                sxdecctrl.scl_dec_ctrl.sgrouptmp = num;
            }
        }
    /* end optional attributes */
    } else
    /* reason = SX_ELEMENT_END */
    {
        let servr_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec.len();
        if servr_len == 0 {
            println!("serve len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ld_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1]
            .ld_vec
            .len();
        if ld_len == 0 {
            println!("ld len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let ln_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec
            .len();
        if ln_len == 0 {
            println!("ln len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let dai_len = sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
            .ln_vec[ln_len - 1]
            .dai_vec
            .len();
        if dai_len == 0 {
            println!("dai len empyt ");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }

        if let Some(ref txt) = sxdecctrl.op_entry_text {
            if sxdecctrl.scl_dec_ctrl.sgrouptmp > 0 {
                /* sGroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store Val*/
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                    [ln_len - 1]
                    .dai_vec[dai_len - 1]
                    .sgval_vec
                    .push(scl_sg_val);

            //scl_sg_val = scl_dai_sg_val_add (sclDecCtrl->scl_dai);
            } else if sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                .ln_vec[ln_len - 1]
                .dai_vec[dai_len - 1]
                .val
                .len()
                > 0
            {
                /* DO NOT allow multiple "Val" without "sGroup": pointer	*/
                /* sclDecCtrl->scl_dai->Val would get overwritten, and never freed.*/
                println!("Multiple 'Val' elements without 'sGroup' not allowed in DAI");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                    .ln_vec[ln_len - 1]
                    .dai_vec[dai_len - 1]
                    .val = txt.trim().to_string();
            }
        } else {
            println!("Error parsing element 'Val' of DAI");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _do_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut scl_do = SclDo::default();

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
        scl_do.name = txt.trim().to_string();
        if !chk_comp_name_legal(&scl_do.name) {
            println!("Illegal character in DO name '{}'", scl_do.name);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
        scl_do.rtype = txt.trim().to_string();
    } else {
        return;
    }
    let lnt_len = sxdecctrl.scl_dec_ctrl.sclinfo.lntype_vec.len();
    if lnt_len == 0 {
        println!("lntype empty");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    sxdecctrl.scl_dec_ctrl.sclinfo.lntype_vec[lnt_len - 1]
        .do_vec
        .push(scl_do);

    /* end required attributes */
}

fn _da_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut required = false;
        let mut scl_da = SclDa::default();

        scl_da.objtype = SCL_OBJTYPE_DA;

        /* start optional attributes */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_da.desc = txt.to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sAddr", required) {
            scl_da.saddr = txt.trim().to_string();
        }
        scl_da.valkind = "Set".to_string();
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("valKind", required) {
            scl_da.valkind = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
            scl_da.rtype = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("count", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_da.count = num;
            } else {
                println!("da count parese err");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dchg", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_da.dchg = true;
            }
        }

        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("qchg", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_da.qchg = true;
            }
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dupd", required) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                scl_da.dupd = true;
            }
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            scl_da.name = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_da.name) {
                println!("Illegal character in DA name '{}'", scl_da.name);
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("bType", required) {
            scl_da.btype = txt.trim().to_string();
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("fc", required) {
            scl_da.fc = txt.trim().to_string();
        } else {
            return;
        }
        let dotype_len = sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec.len();
        if dotype_len == 0 {
            println!("dotype empty");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        // println!("da {:?}",scl_da);
        sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1]
            .da_vec
            .push(scl_da);

        /* end required attributes */
        //scl_da = sclDecCtrl->scl_da = scl_dotype_add_da (sclDecCtrl->sclInfo);
        //DAElements
        sxdecctrl.sx_push(vec![56]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _sdo_sfun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut scl_da = SclDa::default();
    scl_da.objtype = SCL_OBJTYPE_SDO;

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
        scl_da.desc = txt.to_string(); /* Alloc & copy desc string	*/
    }

    /* NOTE: "count" should be present only in Edition 2 SCL files.	*/
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("count", required) {
        if let Ok(num) = txt.trim().parse::<u32>() {
            scl_da.count = num;
        } else {
            println!("ed2 sdo attr count pares err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }

    /* end optional attributes */

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
        scl_da.name = txt.trim().to_string();
        if !chk_comp_name_legal(&scl_da.name) {
            println!("Illegal character in SDO name '{}'", scl_da.name);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
        scl_da.rtype = txt.trim().to_string();
    } else {
        return;
    }
    let dotype_len = sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec.len();
    if dotype_len == 0 {
        println!("dotype empty");
        sxdecctrl.errcode = SX_USER_ERROR;
        return;
    }
    //  println!("dafff {:?}", scl_da);
    sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1]
        .da_vec
        .push(scl_da);

    /* end required attributes */
}
fn _da_val_sefun(sxdecctrl: &mut IcdParseContext2) {
    //println!("da val  kkkkkkkkkkkkkkkkkkkk");
    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sGroup attr NOT present	*/
        /* start optional attributes (don't care about return)	*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sGroup", SCL_ATTR_OPTIONAL) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                sxdecctrl.scl_dec_ctrl.sgrouptmp = num;
            } else {
                println!("da val sgroup pares error");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        }
    /* end optional attributes */
    } else
    /* reason = SX_ELEMENT_END */
    {
        let dotype_len = sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec.len();
        if dotype_len == 0 {
            println!("dotype empty");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let da_desc_len = sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1]
            .da_vec
            .len();
        if da_desc_len == 0 {
            println!("da desc  empty  in dotype");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        if let Some(ref txt) = sxdecctrl.op_entry_text {
            if sxdecctrl.scl_dec_ctrl.sgrouptmp > 0 {
                /* sGroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store Val*/
                sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1].da_vec[da_desc_len - 1]
                    .sgval_vec
                    .push(scl_sg_val);

            //scl_sg_val = scl_dai_sg_val_add (sclDecCtrl->scl_dai);
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1].da_vec[da_desc_len - 1]
                    .val = txt.trim().to_string();
            }
        } else {
            println!("Error parsing element 'Val' of DA");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}

fn _bda_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut required = false;

        let mut scl_bda = SclBda::default();

        /* start optional attributes */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("desc", required) {
            scl_bda.desc = txt.to_string(); /* Alloc & copy desc string	*/
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sAddr", required) {
            scl_bda.saddr = txt.trim().to_string();
        }
        scl_bda.valkind = "Set".to_string(); /* default */
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("valKind", required) {
            scl_bda.valkind = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
            scl_bda.rtype = txt.trim().to_string();
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("count", required) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                scl_bda.count = num;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("bda count parse err");
                return;
            }
        }

        /* end optional attributes */

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
            scl_bda.name = txt.trim().to_string();
            if !chk_comp_name_legal(&scl_bda.name) {
                println!("Illegal character in BDA name '{}'", scl_bda.name);
            }
        } else {
            return;
        }
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("bType", required) {
            scl_bda.btype = txt.trim().to_string();
        } else {
            return;
        }

        /* end required attributes */
        let datype_len = sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec.len();
        if datype_len == 0 {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("datype_len  empty");
            return;
        }
        // println!("bda {:?}", scl_bda);
        sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec[datype_len - 1]
            .bda_vec
            .push(scl_bda);

        //BDAElements
        sxdecctrl.sx_push(vec![58]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _bda_val_sefun(sxdecctrl: &mut IcdParseContext2) {
    //println!("fjjjjjjjjjjjjjjj");
    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sGroup attr NOT present	*/
        /* start optional attributes (don't care about return)	*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sGroup", SCL_ATTR_OPTIONAL) {
            if let Ok(num) = txt.trim().parse::<u32>() {
                sxdecctrl.scl_dec_ctrl.sgrouptmp = num;
            }
        }

    /* end optional attributes */
    } else
    /* reason = SX_ELEMENT_END */
    {
        let datype_len = sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec.len();
        if datype_len == 0 {
            println!("datype empty");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        let bda_desc_len = sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec[datype_len - 1]
            .bda_vec
            .len();
        if bda_desc_len == 0 {
            println!("bda desc  empty  in datype");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
        if let Some(ref txt) = sxdecctrl.op_entry_text {
            if sxdecctrl.scl_dec_ctrl.sgrouptmp > 0 {
                /* sGroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store Val*/
                sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec[datype_len - 1].bda_vec[bda_desc_len - 1]
                    .sgval_vec
                    .push(scl_sg_val);

            //scl_sg_val = scl_dai_sg_val_add (sclDecCtrl->scl_dai);
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.datype_vec[datype_len - 1].bda_vec
                    [bda_desc_len - 1]
                    .val = txt.trim().to_string();
            }
        } else {
            println!("Error parsing element 'Val' of BDA");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _enumval_sefun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    if sxdecctrl.reason == SX_ELEMENT_START {
        let mut scl_enumval = SclEnumval::default();

        /* start required attributes */
        required = true;
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("ord", required) {
            if let Ok(num) = txt.trim().parse::<i32>() {
                scl_enumval.ord = num;
            } else {
                sxdecctrl.errcode = SX_USER_ERROR;
                println!("enum val ord pare err");
                return;
            }
        } else {
            return;
        }
        let enumtype_len = sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec.len();
        if enumtype_len == 0 {
            println!("enumtype len empyt");
            sxdecctrl.errcode = SX_USER_ERROR;

            return;
        }
        sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec[enumtype_len - 1]
            .enumval_vec
            .push(scl_enumval);

    /* end required attributes */
    } else
    /* reason = SX_ELEMENT_END */
    {
        let enumtype_len = sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec.len();
        if enumtype_len == 0 {
            println!("enumtype len empyt");
            sxdecctrl.errcode = SX_USER_ERROR;

            return;
        }
        let enumtype_val_len = sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec[enumtype_len - 1]
            .enumval_vec
            .len();
        if enumtype_val_len == 0 {
            println!("enumtype val len empyt");
            sxdecctrl.errcode = SX_USER_ERROR;

            return;
        }

        if let Some(ref txt) = sxdecctrl.op_entry_text {
            /* If string fits in EnumValBuf, it is copied there & EnumVal is set*/
            /* to point to it. Else, EnumVal is allocated & string is copied to it.*/
            sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec[enumtype_len - 1].enumval_vec
                [enumtype_val_len - 1]
                .enumval = txt.trim().to_string();

            // println!("enu val {:?}",     sxdecctrl.scl_dec_ctrl.sclinfo.enumtype_vec[enumtype_len - 1].enumval_vec
            // [enumtype_val_len - 1]);
        } else {
            sxdecctrl.errcode = SX_USER_ERROR;
            println!("Error parsing element 'EnumVal'");
            return;
        }
    }
}

/************************************************************************/
/*			_GetDirectory_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _getdirectory_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdirectory = true;
    //println!("get directly serei true  1");
}
/************************************************************************/
/*			_GetDataObjectDefinition_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _getdataobjectdefinition_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdataobjectdefinition = true;
    //println!("get directly serei true  2");
}
/************************************************************************/
/*			_DataObjectDirectory_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _dataobjectdirectory_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.dataobjectdirectory = true;
    //println!("get directly serei true  3");
}
/************************************************************************/
/*			_GetDataSetValue_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _getdatasetvalue_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdatasetvalue = true;
    //println!("get directly serei true  4");
}
/************************************************************************/
/*			_SetDataSetValue_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _setdatasetvalue_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.setdatasetvalue = true;
    //println!("get directly serei true  5");
}
/************************************************************************/
/*			_DataSetDirectory_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _datasetdirectory_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.datasetdirectory = true;
    //println!("get directly serei true  6");
}
/************************************************************************/
/*			_ReadWrite_SFun					*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _readwrite_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.readwrite = true;
    //println!("get directly serei true  7");
}
/************************************************************************/
/*			_TimerActivatedControl_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _timeractivatedcontrol_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.timeractivatedcontrol = true;
    //println!("get directly serei true  8");
}
/************************************************************************/
/*			_GetCBValues_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _getcbvalues_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getcbvalues = true;
    //println!("get directly serei true  9");
}
/************************************************************************/
/*			_GSEDir_SFun					*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _gsedir_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.gsedir = true;
    //println!("get directly serei true  10");
}
/************************************************************************/
/*			_FileHandling_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _filehandling_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.filehandling = true;
    //println!("get directly serei true  11");
}
/************************************************************************/
/*			_ConfLdName_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _confldname_sfun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.confldname = true;
    //println!("get directly serei true  12");
}

/************************************************************************/
/*			_ConfLogControl_SFun				*/
/* Fill in structure.							*/
/************************************************************************/
fn _conflogcontrol_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  13 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.conflogcontrol.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.conflogcontrol.enabled = true;
        } else {
            println!("_ConfLogControl_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_GOOSE_SFun					*/
/* Fill in structure.							*/
/************************************************************************/
fn _goose_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  14 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.goose.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.goose.enabled = true;
        } else {
            println!("_GOOSE_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_GSSE_SFun					*/
/* Fill in structure.							*/
/************************************************************************/
fn _gsse_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  15 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.gsse.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.gsse.enabled = true;
        } else {
            println!("_GSSE_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_SMVsc_SFun					*/
/* Fill in structure.							*/
/************************************************************************/
fn _smvsc_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  16 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.smvsc.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.smvsc.enabled = true;
        } else {
            println!("_SMVsc_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_SupSubscription_SFun				*/
/* Fill in structure.							*/
/************************************************************************/
fn _supsubscription_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  17 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.supsubscription.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.supsubscription.enabled = true;
        } else {
            println!("_SupSubscription_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_ConfSigRef_SFun				*/
/* Fill in structure.							*/
/************************************************************************/
fn _confsigref_sfun(sxdecctrl: &mut IcdParseContext2) {
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("max", SCL_ATTR_REQUIRED) {
        if let Ok(max) = txt.parse::<u32>() {
            //println!("get directly serei true  18 {}",max);
            sxdecctrl.scl_dec_ctrl.scl_services.confsigref.max = max;
            sxdecctrl.scl_dec_ctrl.scl_services.confsigref.enabled = true;
        } else {
            println!("_ConfSigRef_SFun max pare err");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
}
/************************************************************************/
/*			_ReportSettings_SFun				*/
/* CRITICAL: default values set earlier by scl_services_init.		*/
/************************************************************************/
fn _reportsettings_sfun(sxdecctrl: &mut IcdParseContext2) {
    /* start optional attributes */
    /* These must be "Dyn", "Conf", or "Fix", so we allow max of 4 characters.*/

    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("cbName", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.cbname = txt;
    }

    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("datSet", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.datset = txt;
    }
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("rptID", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.rptid = txt;
    }
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("optFields", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.optfields = txt;
    }
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("bufTime", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.buftime = txt;
    }
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("trgOps", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.trgops = txt;
    }
    if let Some(txt) = sxdecctrl.scl_get_attr_ptr("intgPd", SCL_ATTR_OPTIONAL) {
        sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.intgpd = txt;
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("resvTms", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.resvtms = true;
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("owner", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            sxdecctrl.scl_dec_ctrl.scl_services.reportsettings.resvtms = true;
        }
    }
    //println!("get directly serei true  19 {:?}", sxdecctrl.scl_dec_ctrl.scl_services.ReportSettings);
    /* end optional attributes */
}

/************************************************************************/
/*			3 解析相关细节结构体 及函数 end					*/
/************************************************************************/
fn chk_mms_ident_legal(name: &str) -> bool {
    for pchar in name.chars() {
        if !(pchar.is_alphanumeric()) && pchar != '_' && pchar != '$' {
            return false;
        }
    }
    true
}
pub fn chk_comp_name_legal(input_str: &str) -> bool {
    for e in input_str.chars() {
        if (!(e.is_ascii_alphanumeric())) && (e != '_') {
            return false;
        }
    }
    true
}
/************************************************************************/
/*			4 解析中间态 辅助结构体 start					*/
/************************************************************************/
// add for rcb info parse
#[derive(Default, Debug, Clone)]
pub struct RcbSubData {
    pub rcb_optflds: [u8; 2], /*cl add for rcb optionfields only */
    pub max: u32,
}

/************************************************************************/
/*			SCL_DEC_CTRL					*/
/* This structure contains data saved during the parsing process.	*/
/************************************************************************/
#[derive(Default, Clone, Debug)]
pub struct SclDecCtrl {
    pub iedname: String,
    pub accesspointname: String,
    pub accesspointfound: bool, /* sd_true if ied and accesspoint found	*/
    pub iednamematched: bool,
    pub accesspointmatched: bool,
    pub sclinfo: Box<SclInfo>,

    pub scl_gse: Box<SclGse>, /* used for "gse" in "communication" section	*/
    pub scl_smv: Box<SclSmv>, /* used for "smv" in "communication" section	*/
    pub scl_ld: Box<SclLd>,   /* used for "ldevice"				*/
    pub scl_ln: Box<SclLn>,   /* used for "ln" (logical node)			*/
    pub scl_rcb: Box<SclRcb>, /* alloc to store reportcontrol info		*/
    pub scl_lcb: Box<SclLcb>, /* alloc to store logcontrol info		*/
    pub trgops: u8,           /* used for reportcontrol or logcontrol.	*/
    /* copied to scl_rcb or scl_lcb.		*/
    pub rcb_sub_data: RcbSubData,
    pub scl_svcb: Box<SclSvcb>,       /* used for "sampledvaluecontrol".	*/
    pub scl_enumval: Box<SclEnumval>, /* used for "enumval".			*/
    pub scl_dai: Box<SclDai>,         /* used for "dai".				*/
    pub scl_da: Box<SclDa>,           /* used for "da".				*/
    pub scl_bda: Box<SclBda>,         /* used for "bda".				*/
    pub flattened: String,            /* created by concatenating values*/
    /* from doi, sdi, and dai elements*/
    pub sgrouptmp: u32, /* temporary "sgroup" value: set when element	*/
    /* start proc'd, used when element end proc'd.	*/
    /* parameters below used for special parsing modes.			*/
    pub parsemode: u32, /* one of "scl_parse_mode_*" defines.	*/
    /* set by main parse functions.		*/
    pub iedtypematched: bool, /* sd_true if iedtype matches one requested*/
    /* used for lnodetype, dotype, datype	*/
    pub iednameproc: String, /* iedname being processed	*/

    pub scl_services: SclServices, /* Info from "Services" section		*/
                                   /* Copied to SCL_SERVER when created.	*/
}

//每一层 的元素表 信息  以及对应出现的次数
pub struct SxElementTblCtrl2 {
    //ST_INT numItems;
    // SxElement *itemTbl;
    //存放的是 SxElement 的index
    pub itemtbl: Vec<usize>,
    pub numocctbl: [u32; SX_MAX_ITEMS_PER_TABLE],
}
pub struct SxElement {
    pub tag: String,
    pub elementflags: u32,
    pub funcptr: Box<dyn FnMut(&mut IcdParseContext2)>,
    // char *user;

    /* Runtime elements: */
    // ST_INT notUsed;
}

//解析出来的tag信息还是要转成utf8
pub struct TagInfo {
    pub tag: String,
    pub atts: HashMap<String, String>,
}
// 重新设计实现 围绕这个context
/// 参考的处理 方法放进去
/// 当前的处理Vec 的typeindex
/// 当前处理的 tag
///
pub struct IcdParseContext2 {
    pub opr_tb: Option<Vec<SxElement>>,
    //当前的状态 是开始 还是结束 用来判断se 函数执行
    pub reason: u32, /* SX_ELEMENT_START, SX_ELEMENT_END	*/

    // pub stat: Option<TagInfo>,

    //存放错误的原因
    pub errcode: u32,
    // >; SX_MAX_STACK_LEVEL],
    pub items: Vec<SxElementTblCtrl2>,
    pub termflag: bool, /* set if you want to terminate decode */
    //SX_MAX_XML_NEST
    pub eltbl: Vec<Option<usize>>,
    //用来存放 scl info
    pub scl_dec_ctrl: SclDecCtrl,
    //最近的元素开始 sxstart 中存放
    pub op_start_tag: Option<TagInfo>,
    //最近的元素内容  在处理内容是存放
    pub op_entry_text: Option<String>,
}

impl IcdParseContext2 {
    fn init_data() -> Self {
        let mut tb = Vec::new();
        tb.append(&mut gen_scl_tb());
        tb.append(&mut gen_sub_scl_tb());
        tb.append(&mut gen_sub_commu_tb());
        tb.append(&mut gen_sub_ied_tb());
        tb.append(&mut gen_sub_datatypetemplate_tb());
        tb.append(&mut gen_subnetworkelements_tb());

        tb.append(&mut gen_connectedapelements_tb());
        tb.append(&mut gen_addresselements_tb());

        tb.append(&mut gen_gseelements_tb());
        tb.append(&mut gen_gseaddresselements_tb());
        tb.append(&mut gen_smvelements_tb());
        tb.append(&mut gen_smvaddresselements_tb());

        tb.append(&mut gen_accesspointelements_tb());
        tb.append(&mut gen_serverelements_tb());
        tb.append(&mut gen_ldeviceelements_tb());
        tb.append(&mut gen_ln0elements_tb());
        tb.append(&mut gen_lnelements_tb());
        tb.append(&mut gen_datasetelements_tb());
        tb.append(&mut gen_reportcontrolelements_tb());
        tb.append(&mut gen_logcontrolelements_tb());
        tb.append(&mut gen_sampledvaluecontrolelements_tb());
        tb.append(&mut gen_inputselements_tb());
        tb.append(&mut gen_doielements_tb());
        tb.append(&mut gen_sdielements_tb());
        tb.append(&mut gen_daielements_tb());
        tb.append(&mut gen_lnodetypeelements_tb());
        tb.append(&mut gen_dotypeelements_tb());
        tb.append(&mut gen_daelements_tb());
        tb.append(&mut gen_datypeelements_tb());
        tb.append(&mut gen_bdaelements_tb());
        tb.append(&mut gen_enumtypeelements_tb());
        tb.append(&mut gen_serviceselements_tb());
        // run initialization here

        IcdParseContext2 {
            opr_tb: Some(tb),
            reason: 0,

            termflag: false,

            //存放错误的原因
            errcode: 0,
            // >; SX_MAX_STACK_LEVEL],
            items: Vec::new(),

            //SX_MAX_XML_NEST
            eltbl: Vec::new(),
            scl_dec_ctrl: SclDecCtrl::default(),

            //最近的元素开始 sxstart 中存放
            op_start_tag: None,
            //最近的元素内容  在处理内容是存放
            op_entry_text: None,
        }
    }
    pub fn sxstartelement(&mut self, start_tag: TagInfo) {
        //SXLOG_DEC1("Start element '%s'", tag);
        /* CRITICAL: This function usually increments "xmlNestLevel" so now	*/
        /*           it must be less than the maximum allowed.		*/
        let destag = "DynAssociationd";
        if destag == start_tag.tag.as_str() {
            println!("start tag 001");
        }
        if self.eltbl.len() < 2 {
            println!(
                "**************now nestleve {} {}",
                self.eltbl.len(),
                start_tag.tag
            );
        }
        if self.eltbl.len() >= SX_MAX_XML_NEST - 1 {
            self.errcode = SX_XML_NEST_TOO_DEEP;
            print!("Start tag {} exceeds max nesting level", start_tag.tag);
            return;
        }
        if self.errcode != SD_SUCCESS && self.errcode != SX_ERR_CONVERT {
            return;
        }
        // println!("opr {} 001 ", start_tag.tag);
        if destag == start_tag.tag.as_str() {
            println!("start tag 002");
        }
        let op_index = self._uibed_find_element(start_tag.tag.as_str());
        if destag == start_tag.tag.as_str() {
            println!("start tag 003 {:?}", op_index);
        }
        // println!("opr {} {:?} 002 ", start_tag.tag, op_index);
        // stackLevelSave = sxdecctrl->itemStackLevel;
        // while (item == NULL && sxdecctrl->itemStackLevel > 0)
        // {
        //   if (sxdecctrl->auto_pop[sxdecctrl->itemStackLevel - 1] == SD_TRUE)
        //   {
        //     _sx_pop(sxdecctrl, SD_TRUE);
        //     item = _uibed_find_element(sxdecctrl, tag, &numOccPtr);
        //   }
        //   else
        //     break;
        // }
        if op_index.is_some() {
            self.op_start_tag = Some(start_tag);
            let index = op_index.unwrap();
            let elementflags = self.opr_tb.as_ref().unwrap()[index].elementflags;
            self.reason = SX_ELEMENT_START;
            let mut opr_tb = self.opr_tb.take().unwrap();
            if (elementflags & SX_ELF_CSTART) != 0 {
                (*opr_tb[index].funcptr)(self);
            }
            self.opr_tb = Some(opr_tb);
            self.eltbl.push(Some(index));

            self.op_entry_text = None;
        } else {
            self.eltbl.push(None);
            _scl_unknown_el_start2(self, start_tag.tag.as_str());
        }
    }

    pub fn sxendelement(&mut self, end_tag: TagInfo) {
        //println!("End element   {}", end_tag.tag);
        /* CRITICAL: This function usually decrements "xmlNestLevel" so now	*/
        /*           it must be > 0.						*/
        if self.eltbl.len() <= 0 {
            self.errcode = SX_XML_MALFORMED;
            println!("Unexpected End tag {}. Invalid nesting.", end_tag.tag);
            return;
        }
        if self.errcode != SD_SUCCESS && self.errcode != SX_ERR_CONVERT {
            return;
        }

        let item = self.eltbl.pop();
        let item = item.unwrap();

        if item.is_some() {
            let item_index = item.unwrap();
            if let Some(el) = self.opr_tb.as_ref().unwrap().get(item_index) {
                if !check_eq_2bs(end_tag.tag.as_bytes(), el.tag.as_bytes())
                /* verify end tag */
                {
                    self.errcode = SX_XML_MALFORMED;
                    println!("XML malformed: found {}, expected {}", end_tag.tag, el.tag);
                } else {
                    if (el.elementflags & SX_ELF_CEND) != 0 {
                        //sxdecctrl->item = item;
                        self.reason = SX_ELEMENT_END;

                        let mut opr_tb = self.opr_tb.take().unwrap();

                        (*opr_tb[item_index].funcptr)(self);

                        self.opr_tb = Some(opr_tb);
                        // self.stat = Some(end_tag);
                    }
                }
            }
        } else {
            // println!("unknow end {}", end_tag.tag);
        }
    }

    //寻找指定的tag 同时把 判断次数放进去
    pub fn _uibed_find_element(
        &mut self,
        tag: &str, /* , ST_INT **numOccPtrOut*/
    ) -> Option<usize> {
        let mut find = false;
        let mut res_index = 0;
        let mut find_index = 0;

        let opr_tb = self.opr_tb.as_ref().unwrap();
        if self.items.len() > 0 {
            let last_index = self.items.len() - 1;
            for (index, e) in self.items[last_index].itemtbl.iter().enumerate() {
                if *e < opr_tb.len() {
                    if check_eq_2bs(opr_tb[*e].tag.as_bytes(), tag.as_bytes()) {
                        find = true;
                        find_index = index;
                        res_index = *e;
                        //++(*numOccPtr);
                    }
                }
            }
            if find {
                let elementflags = opr_tb[res_index].elementflags;
                if self.items[last_index].numocctbl[find_index] != 0
                    && ((elementflags & SX_ELF_RPT) == 0)
                {
                    self.errcode = SX_DUPLICATE_NOT_ALLOWED;
                    println!("Duplicate of element {} not allowed", tag);
                }
                self.items[last_index].numocctbl[find_index] += 1;
                return Some(res_index);
            }
        }
        return None;
    }

    pub fn sx_push(&mut self, itemtbl: Vec<usize>) {
        /* Do some sanity checks first */
        if self.items.len() >= SX_MAX_STACK_LEVEL {
            self.errcode = SX_XML_NEST_TOO_DEEP;
            return;
        }
        if itemtbl.len() > SX_MAX_ITEMS_PER_TABLE {
            self.errcode = SX_ELEMENT_TBL_TOO_BIG;
            return;
        }

        self.items.push(SxElementTblCtrl2 {
            //ST_INT numItems;
            // SxElement *itemTbl;
            //存放的是 SxElement 的index
            itemtbl: itemtbl,
            numocctbl: [0; SX_MAX_ITEMS_PER_TABLE],
        });
    }

    pub fn sx_pop(&mut self) {
        if self.items.len() > 0 {
            self.items.pop();
        }
    }

    //获取tag 指定名称的属性
    pub fn scl_get_attr_ptr(&mut self, name: &str, required: bool) -> Option<String> {
        if let Some(ref item) = self.op_start_tag {
            if let Some(val) = item.atts.get(name) {
                let res = val.clone();
                return Some(res);
            } else {
                if required {
                    println!(
                        "SCL PARSE: In element {}, required attribute {} not found",
                        item.tag, name
                    );
                }
            }
        }
        if required {
            self.errcode = SX_ERR_REQUIRED_ATTR_NOT_FOUND;
            self.termflag = true;
        }
        return None;
    }
}

//生成scl 处理表  scl
fn gen_scl_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);
    tb.push(SxElement {
        tag: String::from("SCL"), /*INDEX 0 */
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_scl_sefun),
    });
    //{"SCL", 		SX_ELF_CSTARTEND,		_SCL_SEFun, NULL, 0}
    return tb;
}

//生成scl 子元素 处理表 scl/
fn gen_sub_scl_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(4);
    tb.push(SxElement {
        tag: String::from("Header"), /*INDEX 1 */
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_header_sfun),
    });
    tb.push(SxElement {
        tag: String::from("Communication"), /*INDEX 2 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_communication_sefun),
    });
    tb.push(SxElement {
        tag: String::from("IED"), /*INDEX 3 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_ied_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DataTypeTemplates"), /*INDEX 4 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_datatypetemplates_sefun),
    });

    return tb;
}

// {"SubNetwork",      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SubNetwork_SEFun, NULL, 0}

//Communication 子元素 处理表 Communication/
fn gen_sub_commu_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);
    tb.push(SxElement {
        tag: String::from("SubNetwork"), /*INDEX 5 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_subnetwork_sefun),
    });

    return tb;
}

// SxElement IEDElements[] =
// {
//   {"Services",		SX_ELF_CSTARTEND,		Services_SEFun, NULL, 0},
//   {"AccessPoint",      	SX_ELF_CSTARTEND|SX_ELF_RPT, 	_AccessPoint_SEFun, NULL, 0}
// };
//IEDElements 子元素 处理表 IEDElements/
fn gen_sub_ied_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);
    tb.push(SxElement {
        tag: String::from("Services"), /*INDEX 6 */
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(services_sefun),
    });
    tb.push(SxElement {
        tag: String::from("AccessPoint"), /*INDEX 7 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_accesspoint_sefun),
    });

    return tb;
}

// SxElement DataTypeTemplatesElements[] =
// {
//   {"LNodeType",  	SX_ELF_CSTARTEND|SX_ELF_RPT,	_LNodeType_SEFun, NULL, 0},
//   {"DOType",  		SX_ELF_CSTARTEND|SX_ELF_RPT,	_DOType_SEFun, NULL, 0},
//   {"DAType",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAType_SEFun, NULL, 0},
//   {"EnumType", 		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_EnumType_SEFun, NULL, 0}
// };

//DataTypeTemplatesElements 子元素 处理表 DataTypeTemplatesElements/
fn gen_sub_datatypetemplate_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(4);
    tb.push(SxElement {
        tag: String::from("LNodeType"), /*INDEX 8*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_lnodetype_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DOType"), /*INDEX 9 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_dotype_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DAType"), /*INDEX 10*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_datype_sefun),
    });
    tb.push(SxElement {
        tag: String::from("EnumType"), /*INDEX 11 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_enumtype_sefun),
    });

    return tb;
}

// SxElement SubNetworkElements[] =
// {
//   /* NOTE: "bitRate" and "Text" elements ignored.	*/
//   {"ConnectedAP",      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_ConnectedAP_SEFun, NULL, 0}
// };
//SubNetworkElements 子元素 处理表 SCL/Communication/SubNetwork/
fn gen_subnetworkelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);
    tb.push(SxElement {
        tag: String::from("ConnectedAP"), /*INDEX 12*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_connectedap_sefun),
    });

    return tb;
}

// SxElement ConnectedAPElements[] =
// {
//   /* DEBUG: Ignore "PhyConn".	*/
//   {"Address",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_Address_SEFun, NULL, 0},
//   {"GSE",	      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_GSE_SEFun, NULL, 0},
//   {"SMV",	      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SMV_SEFun, NULL, 0}
// };
//ConnectedAPElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements
fn gen_connectedapelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(3);
    tb.push(SxElement {
        tag: String::from("Address"), /*INDEX 13*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_address_sefun),
    });
    tb.push(SxElement {
        tag: String::from("GSE"), /*INDEX 14*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_gse_sefun),
    });
    tb.push(SxElement {
        tag: String::from("SMV"), /*INDEX 15*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_smv_sefun),
    });

    return tb;
}

// SxElement AddressElements[] =
// {
//   {"P",			SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_Address_P_SEFun, NULL, 0}
// };
//AddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/AddressElements
fn gen_addresselements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);
    tb.push(SxElement {
        tag: String::from("P"), /*INDEX 16*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_address_p_sefun),
    });

    return tb;
}

// SxElement GSEElements[] =
// {
//   {"Address",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_GSE_Address_SEFun, NULL, 0},
//   {"MinTime",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_GSE_MinTime_SEFun, NULL, 0},
//   {"MaxTime",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_GSE_MaxTime_SEFun, NULL, 0}
// };
//GSEElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/GSEElements
fn gen_gseelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(3);
    tb.push(SxElement {
        tag: String::from("Address"), /*INDEX 17*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_gse_address_sefun),
    });

    tb.push(SxElement {
        tag: String::from("MinTime"), /*INDEX 18*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_gse_mintime_sefun),
    });

    tb.push(SxElement {
        tag: String::from("MaxTime"), /*INDEX 19*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_gse_maxtime_sefun),
    });

    return tb;
}

// SxElement GSEAddressElements[] =
// {
//   {"P",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_GSE_Address_P_SEFun, NULL, 0}
// };
//GSEAddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/GSEElements/GSEAddressElements
fn gen_gseaddresselements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("P"), /*INDEX 20*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_gse_address_p_sefun),
    });

    return tb;
}

// SxElement SMVElements[] =
// {
//   {"Address",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_SMV_Address_SEFun, NULL, 0}
// };
//SMVElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/SMVElements
fn gen_smvelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Address"), /*INDEX 21*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_smv_address_sefun),
    });

    return tb;
}
// SxElement SMVAddressElements[] =
// {
//   {"P",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SMV_Address_P_SEFun, NULL, 0}
// };
//SMVAddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/SMVElements/SMVAddressElements
fn gen_smvaddresselements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("P"), /*INDEX 22*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_smv_address_p_sefun),
    });

    return tb;
}

// SxElement AccessPointElements[] =
// {
//   {"Server",      	SX_ELF_CSTARTEND, 		_Server_SEFun, NULL, 0}
// };
//Server 子元素 处理表 SCL/IED/Server、AccessPointElements
fn gen_accesspointelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Server"), /*INDEX 23*/
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_server_sefun),
    });

    return tb;
}

// SxElement ServerElements[] =
// {
//   {"LDevice",      	SX_ELF_CSTARTEND|SX_ELF_RPT,	_LDevice_SEFun, NULL, 0}
// };
//ServerElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements
fn gen_serverelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("LDevice"), /*INDEX 24*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_ldevice_sefun),
    });

    return tb;
}

// SxElement LDeviceElements[] =
// {
//   {"LN0",      		SX_ELF_CSTARTEND,		_LN_SEFun, NULL, 0},
//   {"LN",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_LN_SEFun, NULL, 0}
// };
//LDeviceElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements
fn gen_ldeviceelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("LN0"), /*INDEX 25*/
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_ln_sefun),
    });
    tb.push(SxElement {
        tag: String::from("LN"), /*INDEX 26*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_ln_sefun),
    });

    return tb;
}

// SxElement LN0Elements[] =
// {
//   {"DataSet",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DataSet_SEFun, NULL, 0},
//   {"ReportControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_ReportControl_SEFun, NULL, 0},
//   {"DOI",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DOI_SEFun, NULL, 0},
//   {"SampledValueControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SampledValueControl_SEFun, NULL, 0},
//   {"LogControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_LogControl_SEFun, NULL, 0},
//   {"SettingControl",	SX_ELF_CSTART|SX_ELF_OPTRPT,	_SettingControl_SFun, NULL, 0},
//   {"GSEControl",	SX_ELF_CSTART|SX_ELF_OPTRPT,	_GSEControl_SFun, NULL, 0},
//   {"Inputs",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_Inputs_SEFun, NULL, 0}
// };
//LN0Elements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LN0Elements
fn gen_ln0elements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(8);

    tb.push(SxElement {
        tag: String::from("DataSet"), /*INDEX 27*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_dataset_sefun),
    });
    tb.push(SxElement {
        tag: String::from("ReportControl"), /*INDEX 28*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_reportcontrol_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DOI"), /*INDEX 29*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_doi_sefun),
    });
    tb.push(SxElement {
        tag: String::from("SampledValueControl"), /*INDEX 30*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_sampledvaluecontrol_sefun),
    });
    tb.push(SxElement {
        tag: String::from("LogControl"), /*INDEX 31*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_logcontrol_sefun),
    });
    tb.push(SxElement {
        tag: String::from("SettingControl"), /*INDEX 32*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_settingcontrol_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GSEControl"), /*INDEX 33*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_gsecontrol_sfun),
    });
    tb.push(SxElement {
        tag: String::from("Inputs"), /*INDEX 34*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_inputs_sefun),
    });

    return tb;
}
// SxElement LNElements[] =
// {
//   {"DataSet",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DataSet_SEFun, NULL, 0},
//   {"ReportControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_ReportControl_SEFun, NULL, 0},
//   {"DOI",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DOI_SEFun, NULL, 0},
//   {"SampledValueControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SampledValueControl_SEFun, NULL, 0},
//   {"LogControl",	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_LogControl_SEFun, NULL, 0},
//   {"Inputs",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_Inputs_SEFun, NULL, 0}
// };

//LNElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements
fn gen_lnelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(6);

    tb.push(SxElement {
        tag: String::from("DataSet"), /*INDEX 35*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_dataset_sefun),
    });
    tb.push(SxElement {
        tag: String::from("ReportControl"), /*INDEX 36*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_reportcontrol_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DOI"), /*INDEX 37*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_doi_sefun),
    });

    tb.push(SxElement {
        tag: String::from("SampledValueControl"), /*INDEX 38*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_sampledvaluecontrol_sefun),
    });
    tb.push(SxElement {
        tag: String::from("LogControl"), /*INDEX 39*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_logcontrol_sefun),
    });

    tb.push(SxElement {
        tag: String::from("Inputs"), /*INDEX 40*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_inputs_sefun),
    });

    return tb;
}

// SxElement DataSetElements[] =
// {
//   {"FCDA",  		SX_ELF_CSTART|SX_ELF_RPT,	_FCDA_SFun, NULL, 0}
// };
//DataSetElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements、DataSetElements
fn gen_datasetelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("FCDA"), /*INDEX 41*/
        elementflags: SX_ELF_CSTART | SX_ELF_RPT,
        funcptr: Box::new(_fcda_sfun),
    });

    return tb;
}

// SxElement ReportControlElements[] =
// {
//   {"TrgOps",  		SX_ELF_CSTART|SX_ELF_OPT,	_TrgOps_SFun, NULL, 0},
//   {"OptFields",		SX_ELF_CSTART,			_OptFlds_SFun, NULL, 0},
//   {"RptEnabled",	SX_ELF_CSTART|SX_ELF_OPT,	_RptEnabled_SFun, NULL, 0}
// };
//ReportControlElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements/ReportControlElements
fn gen_reportcontrolelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(3);

    tb.push(SxElement {
        tag: String::from("TrgOps"), /*INDEX 42*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_trgops_sfun),
    });
    tb.push(SxElement {
        tag: String::from("OptFields"), /*INDEX 43*/
        elementflags: SX_ELF_CSTART,
        funcptr: Box::new(_optflds_sfun),
    });
    tb.push(SxElement {
        tag: String::from("RptEnabled"), /*INDEX 44*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_rptenabled_sfun),
    });

    return tb;
}

// SxElement LogControlElements[] =
// {
//   {"TrgOps",  		SX_ELF_CSTART|SX_ELF_OPT,	_TrgOps_SFun, NULL, 0}
// };
//LogControlElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements/LogControlElements
fn gen_logcontrolelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("TrgOps"), /*INDEX 45*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_trgops_sfun),
    });

    return tb;
}

// SxElement SampledValueControlElements[] =
// {
//   {"SmvOpts",  		SX_ELF_CSTART,			_SmvOpts_SFun, NULL, 0}
// };
fn gen_sampledvaluecontrolelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("SmvOpts"), /*INDEX 46*/
        elementflags: SX_ELF_CSTART,
        funcptr: Box::new(_smvopts_sfun),
    });

    return tb;
}

// SxElement InputsElements[] =
// {
// /* DEBUG: Text and Private elements ignored??	*/
//   {"ExtRef",  		SX_ELF_CSTART|SX_ELF_OPTRPT,	_ExtRef_SFun, NULL, 0}
// };
fn gen_inputselements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("ExtRef"), /*INDEX 47*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_extref_sfun),
    });

    return tb;
}

// SxElement DOIElements[] =
// {
//   {"SDI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SDI_SEFun, NULL, 0},
//   {"DAI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_SEFun, NULL, 0}
// };
fn gen_doielements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("SDI"), /*INDEX 48*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_sdi_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DAI"), /*INDEX 49*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_dai_sefun),
    });

    return tb;
}

/* SDI can be nested under itself indefinitely */
// SxElement SDIElements[] =
// {
//   {"SDI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SDI_SEFun, NULL, 0},
//   {"DAI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_SEFun, NULL, 0}
// };
fn gen_sdielements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("SDI"), /*INDEX 50*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_sdi_sefun),
    });
    tb.push(SxElement {
        tag: String::from("DAI"), /*INDEX 51*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_dai_sefun),
    });

    return tb;
}

// SxElement DAIElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_Val_SEFun, NULL, 0}
// };

fn gen_daielements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 52*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_dai_val_sefun),
    });

    return tb;
}

// SxElement LNodeTypeElements[] =
// {
//   {"DO",  		SX_ELF_CSTART|SX_ELF_RPT,	_DO_SFun, NULL, 0}
// };
fn gen_lnodetypeelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("DO"), /*INDEX 53*/
        elementflags: SX_ELF_CSTART | SX_ELF_RPT,
        funcptr: Box::new(_do_sfun),
    });

    return tb;
}

// SxElement DOTypeElements[] =
// {
//   {"DA",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DA_SEFun, NULL, 0},
//   {"SDO",  		SX_ELF_CSTART|SX_ELF_OPTRPT,	_SDO_SFun, NULL, 0}
// };

fn gen_dotypeelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("DA"), /*INDEX 54*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_da_sefun),
    });
    tb.push(SxElement {
        tag: String::from("SDO"), /*INDEX 55*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_sdo_sfun),
    });

    return tb;
}

// SxElement DAElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DA_Val_SEFun, NULL, 0}
// };
fn gen_daelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 56*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_da_val_sefun),
    });

    return tb;
}

// SxElement DATypeElements[] =
// {
//   {"BDA",  		SX_ELF_CSTARTEND|SX_ELF_RPT,	_BDA_SEFun, NULL, 0}
// };
fn gen_datypeelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("BDA"), /*INDEX 57*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_bda_sefun),
    });

    return tb;
}

// SxElement BDAElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_BDA_Val_SEFun, NULL, 0}
// };

fn gen_bdaelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 58*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_bda_val_sefun),
    });

    return tb;
}

// SxElement EnumTypeElements[] =
// {
//   {"EnumVal",  		SX_ELF_CSTARTEND|SX_ELF_RPT,	_EnumVal_SEFun, NULL, 0}
// };

fn gen_enumtypeelements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("EnumVal"), /*INDEX 59*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_enumval_sefun),
    });

    return tb;
}
// SxElement ServicesElements[] =
// {
//   /* These entries for "tServiceYesNo".	*/
//   {"GetDirectory",		SX_ELF_CSTART|SX_ELF_OPT,	_GetDirectory_SFun, NULL, 0},
//   {"GetDataObjectDefinition",	SX_ELF_CSTART|SX_ELF_OPT,	_GetDataObjectDefinition_SFun, NULL, 0},
//   {"DataObjectDirectory",	SX_ELF_CSTART|SX_ELF_OPT,	_DataObjectDirectory_SFun, NULL, 0},
//   {"GetDataSetValue",		SX_ELF_CSTART|SX_ELF_OPT,	_GetDataSetValue_SFun, NULL, 0},
//   {"SetDataSetValue",		SX_ELF_CSTART|SX_ELF_OPT,	_SetDataSetValue_SFun, NULL, 0},
//   {"DataSetDirectory",		SX_ELF_CSTART|SX_ELF_OPT,	_DataSetDirectory_SFun, NULL, 0},
//   {"ReadWrite",			SX_ELF_CSTART|SX_ELF_OPT,	_ReadWrite_SFun, NULL, 0},
//   {"TimerActivatedControl",	SX_ELF_CSTART|SX_ELF_OPT,	_TimerActivatedControl_SFun, NULL, 0},
//   {"GetCBValues",		SX_ELF_CSTART|SX_ELF_OPT,	_GetCBValues_SFun, NULL, 0},
//   {"GSEDir",			SX_ELF_CSTART|SX_ELF_OPT,	_GSEDir_SFun, NULL, 0},
//   {"FileHandling",		SX_ELF_CSTART|SX_ELF_OPT,	_FileHandling_SFun, NULL, 0},
//   {"ConfLdName",		SX_ELF_CSTART|SX_ELF_OPT,	_ConfLdName_SFun, NULL, 0},
//   /* These entries for "tServiceWithMax".	*/
//   {"ConfLogControl",		SX_ELF_CSTART|SX_ELF_OPT,	_ConfLogControl_SFun, NULL, 0},
//   {"GOOSE",			SX_ELF_CSTART|SX_ELF_OPT,	_GOOSE_SFun, NULL, 0},
//   {"GSSE",			SX_ELF_CSTART|SX_ELF_OPT,	_GSSE_SFun, NULL, 0},
//   {"SMVsc",			SX_ELF_CSTART|SX_ELF_OPT,	_SMVsc_SFun, NULL, 0},
//   {"SupSubscription",		SX_ELF_CSTART|SX_ELF_OPT,	_SupSubscription_SFun, NULL, 0},
//   {"ConfSigRef",		SX_ELF_CSTART|SX_ELF_OPT,	_ConfSigRef_SFun, NULL, 0},
//   /* More complex entries.	*/
//   /* DEBUG: TO DO: Add entries for DynAssociation, SettingGroups, ConfDataSet,*/
//   /*        DynDataSet, LogSettings, GSESettings, SMVSettings, ConfLNs.*/
//   {"ReportSettings",		SX_ELF_CSTART|SX_ELF_OPT,	_ReportSettings_SFun, NULL, 0}
// };
pub fn gen_serviceselements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(19);

    tb.push(SxElement {
        tag: String::from("GetDirectory"), /*INDEX 60*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_getdirectory_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GetDataObjectDefinition"), /*INDEX 61*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_getdataobjectdefinition_sfun),
    });
    tb.push(SxElement {
        tag: String::from("DataObjectDirectory"), /*INDEX 62*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_dataobjectdirectory_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GetDataSetValue"), /*INDEX 63*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_getdatasetvalue_sfun),
    });
    tb.push(SxElement {
        tag: String::from("SetDataSetValue"), /*INDEX 64*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_setdatasetvalue_sfun),
    });
    tb.push(SxElement {
        tag: String::from("DataSetDirectory"), /*INDEX 65*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_datasetdirectory_sfun),
    });
    tb.push(SxElement {
        tag: String::from("ReadWrite"), /*INDEX 66*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_readwrite_sfun),
    });

    tb.push(SxElement {
        tag: String::from("TimerActivatedControl"), /*INDEX 67*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_timeractivatedcontrol_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GetCBValues"), /*INDEX 68*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_getcbvalues_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GSEDir"), /*INDEX 69*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_gsedir_sfun),
    });
    tb.push(SxElement {
        tag: String::from("FileHandling"), /*INDEX 70*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_filehandling_sfun),
    });
    tb.push(SxElement {
        tag: String::from("ConfLdName"), /*INDEX 71*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_confldname_sfun),
    });

    //   /* These entries for "tServiceWithMax".	*/
    tb.push(SxElement {
        tag: String::from("ConfLogControl"), /*INDEX 72*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_conflogcontrol_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GOOSE"), /*INDEX 73*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_goose_sfun),
    });
    tb.push(SxElement {
        tag: String::from("GSSE"), /*INDEX 74*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_gsse_sfun),
    });
    tb.push(SxElement {
        tag: String::from("SMVsc"), /*INDEX 75*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_smvsc_sfun),
    });
    tb.push(SxElement {
        tag: String::from("SupSubscription"), /*INDEX 76*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_supsubscription_sfun),
    });
    tb.push(SxElement {
        tag: String::from("ConfSigRef"), /*INDEX 77*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_confsigref_sfun),
    });

    //   /* More complex entries.	*/
    //   /* DEBUG: TO DO: Add entries for DynAssociation, SettingGroups, ConfDataSet,*/
    //   /*        DynDataSet, LogSettings, GSESettings, SMVSettings, ConfLNs.*/
    tb.push(SxElement {
        tag: String::from("ReportSettings"), /*INDEX 78*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_reportsettings_sfun),
    });

    return tb;
}

pub fn check_eq_2bs(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    if a.len() == 0 {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }

    return true;
}

// 大小不敏感的  比较字符串是否相等
pub fn check_eq_2str_incaseinse(a: &str, b: &str) -> bool {
    let ai = a.to_ascii_lowercase();
    let bi = b.to_ascii_lowercase();

    ai == bi
}

fn _scl_unknown_el_start2(_cxt: &mut IcdParseContext2, tag: &str) -> bool {
    println!("SCL PARSE: Unneeded or unknown element '{}'", tag);
    return true;
}

/************************************************************************/
/*			_scl_unknown_el_end				*/
/************************************************************************/

fn _scl_unknown_el_end2(_cxt: &mut IcdParseContext2, _tag: &str) -> bool {
    return true;
}

pub fn asciitoobjid(astr: &str) -> crate::Result<MmsObjId> {
    let mut objid = MmsObjId::default();

    let sp_str = astr.split_whitespace();
    for e in sp_str {
        if objid.num_comps >= MAX_OBJID_COMPONENTS as u32 {
            bail!("exceed max objid level");
        }
        let ne = e.trim().trim_matches('\"');
        if let Ok(num) = ne.parse() {
            objid.comps[objid.num_comps as usize] = num;
            objid.num_comps += 1;
        } else {
            bail!(" objid parse err");
        }
    }
    if objid.num_comps == 0 {
        bail!("empty objid get");
    } else {
        return Ok(objid);
    }
}
/************************************************************************/
/*			 construct_flattened				*/
/* Construct a flattened variable name from DOI, SDI, DAI names.	*/
/************************************************************************/
fn construct_flattened(
    flattened: &mut String,
    maxlen: usize,
    name: &str,
    ix: &str,
) -> crate::Result<()> {
    let mut ixlen = ix.len();

    /* Calc space needed for optional [ix]	*/
    if ixlen != 0 {
        ixlen = ixlen + 2; /* string plus brackets	*/
    }

    /* Make sure there is room for [ix] and "$"	*/
    if flattened.len() + name.len() + ixlen + 1 <= maxlen {
        /* If flattened is now empty, just copy name, else add "$" then name.*/
        if flattened.len() == 0 {
            *flattened += name;
        } else {
            *flattened += "$";
            *flattened += name;
            //   strcat (flattened, "$");
            //   strcat (flattened, name);
        }
        if ixlen != 0 {
            /* Add 'ix' to flattened if necessary.	*/
            *flattened += "[";
            *flattened += ix;
            *flattened += "]";
            //   strcat (flattened, "[");
            //   strcat (flattened, ix);
            //   strcat (flattened, "]");
        }
        Ok(())
    } else {
        /* flattened is big, so this error should never occur with normal SCL.*/
        bail!(format!(
            "ERROR: not enough space to add name '{}' to flattened name '{}'",
            name, flattened
        ))
        //retCode = SD_FAILURE;
    }
    // return (retCode);
}
///辅助函数 用来解析icd tag 为拥有的strign

fn get_start_tag_info<'a, B: BufRead>(
    btstart: &BytesStart<'a>,
    reader: &Reader<B>,
) -> crate::Result<TagInfo> {
    let tag_name = btstart.name();
    let res = from_utf8(tag_name.as_ref())?;

    let tag = res.to_string();
    let mut atts: HashMap<String, String> = HashMap::new();
    let atts_u8 = btstart.attributes();
    for att in atts_u8 {
        if att.is_err() {
            bail!(Box::new(att.unwrap_err()));
        }
        let att = att.unwrap();
        let value = att.decode_and_unescape_value(reader)?.to_string();
        let key = att.key;
        let key = from_utf8(key.as_ref())?;
        let key = key.to_string();
        atts.insert(key, value);
    }

    Ok(TagInfo {
        tag: tag,
        atts: atts,
    })
}

fn get_end_tag_info<'a, B: BufRead>(
    btend: &BytesEnd<'a>,
    _reader: &Reader<B>,
) -> crate::Result<TagInfo> {
    let tag_name = btend.name();
    let res = from_utf8(tag_name.as_ref())?;

    let tag = res.to_string();
    let atts: HashMap<String, String> = HashMap::new();

    Ok(TagInfo {
        tag: tag,
        atts: atts,
    })
}

/************************************************************************/
/*			4 解析中间态 辅助结构体 end					*/
/************************************************************************/
