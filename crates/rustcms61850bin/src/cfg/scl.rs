use quick_xml::{
    events::{BytesEnd, BytesStart, BytesText, Event},
    Reader,
};
use std::net::Ipv4Addr;

use anyhow::{bail, Context};
use mac_address::MacAddress;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;
use std::str::from_utf8;
use std::str::FromStr;
use tokio::fs;
pub const MAX_IDENT_LEN: usize = 64; /* length of an Identifier variable	*/

/* Define larger PSEL,SSEL for compatibility with existing applications.*/
pub const MAX_PSEL_LEN: usize = 16; /* International Std Profile recommends 4*/
pub const MAX_SSEL_LEN: usize = 16; /* GOSIP Ver2 recommends len of 2	*/

/* Define larger TSEL for compatibility with existing applications.	*/
pub const MAX_TSEL_LEN: usize = 32; /* GOSIP Ver2 recommends len of 2	*/

pub const MAX_OBJID_COMPONENTS: usize = 16;

pub const MAX_VALKIND_LEN: usize = 4; /* Spec, Conf, RO, or Set		*/

pub const CLNP_MAX_LEN_MAC: usize = 6; /* Max len of mac addr*/

pub const MAX_CDC_LEN: usize = 50; /* SPS, DPS, etc. (CURVE is longest	*/
/* predefined CDC but user may define others)*/
pub const MAX_FC_LEN: usize = 2; /* ST, MX, etc.				*/

/* This def used for flattened leaf names (longer to allow array indices)*/
/* Allow 7 extra char for 5 digit array index & brackets, like [10000]	*/
pub const MAX_FLAT_LEN: usize = MAX_IDENT_LEN + 7;

pub const MVL61850_MAX_RPTID_LEN: usize = 65;
pub const MVL61850_MAX_OBJREF_LEN: usize = 129; /* Value specified by Tissue 141*/

pub const SCL_PARSE_MODE_CID: usize = 0;

pub const SX_MAX_STACK_LEVEL: usize = 1000;
pub const SX_MAX_ITEMS_PER_TABLE: usize = 50;

pub const SX_MAX_XML_NEST: usize = 30;

/* elementflags defines; bitmasked */
pub const SX_ELF_CSTART: u32 = 0x0001;
pub const SX_ELF_CEND: u32 = 0x0002;
pub const SX_ELF_CSTARTEND: u32 = 0x0003;

pub const SX_ELF_RPT: u32 = 0x0008;
pub const SX_ELF_OPT: u32 = 0x0004;
pub const SX_ELF_OPTRPT: u32 = 0x000C;

pub const SX_ELF_EMPTYOK: u32 = 0x0010;

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

/* Normal errors - continue with parse */
pub const SX_ERR_CONVERT: u32 = 100;

pub const SD_TRUE: u32 = 1;
pub const SD_FALSE: u32 = 0;
pub const SD_SUCCESS: u32 = 0;
pub const SD_FAILURE: u32 = 1;
pub const SD_BIG_ENDIAN: u32 = 0;
pub const SD_LITTLE_ENDIAN: u32 = 1;

/* defines for 'reason' */
pub const SX_ELEMENT_START: u32 = 1;
pub const SX_ELEMENT_END: u32 = 2;

pub const SCL_ATTR_OPTIONAL: bool = false; /* attribute is optional	*/
pub const SCL_ATTR_REQUIRED: bool = true; /* attribute is required	*/

pub const SCL_NAMESTRUCTURE_IEDNAME: u32 = 0; /* value="IEDName"	*/
pub const SCL_NAMESTRUCTURE_FUNCNAME: u32 = 1; /* value="FuncName"	*/

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

/* Bit numbers in optflds bitstring (configured by SmvOpts in SCL file)	*/
pub const SVOPT_BITNUM_REFRTM: usize = 0;
pub const SVOPT_BITNUM_SMPSYNCH: usize = 1; /* Ignored for Edition 2	*/
pub const SVOPT_BITNUM_SMPRATE: usize = 2;
pub const SVOPT_BITNUM_DATSET: usize = 3; /* Edition 2 only	*/
pub const SVOPT_BITNUM_SECURITY: usize = 4; /* Edition 2 only	*/

/* These defines used in SCL_DA struct to differentiate between structs	*/
/* containing DA info and structs containing SDO info.			*/
pub const SCL_OBJTYPE_DA: u32 = 0;
pub const SCL_OBJTYPE_SDO: u32 = 1;

/* Macros to access each individual bit of any bitstring.		*/
pub fn bstr_bit_set_on(buf: &mut [u8], bitnum: usize) {
    let byte_index = bitnum / 8;
    let bit_index = bitnum & 7;
    if byte_index >= buf.len() {
        return;
    }
    buf[byte_index] |= 0x80 >> (bit_index);
}

pub fn bstr_bit_set_off(buf: &mut [u8], bitnum: usize) {
    let byte_index = bitnum / 8;
    let bit_index = bitnum & 7;
    if byte_index >= buf.len() {
        return;
    }
    buf[byte_index] &= !(0x80 >> (bit_index));
}
// 	( ((ST_UINT8 *)(ptr))[(bitnum)/8] |= (0x80>>((bitnum)&7)) )
// #define bstr_bit_set_off(ptr,bitnum) \
// 	( ((ST_UINT8 *)(ptr))[(bitnum)/8] &= ~(0x80>>((bitnum)&7)) )

// /* bstr_bit_get returns 0 if bit is clear, 1 if bit is set.	*/
// #define bstr_bit_get(ptr,bitnum) \
// 	(( ((ST_UINT8 *)(ptr))[(bitnum)/8] &  (0x80>>((bitnum)&7)) ) ? 1:0)

pub fn bstr_bit_get(buf: &[u8], bitnum: usize) -> bool {
    let byte_index = bitnum / 8;
    let bit_index = bitnum & 7;
    if byte_index >= buf.len() {
        return false;
    }
    if buf[byte_index] & (0x80 >> (bit_index)) != 0 {
        return true;
    } else {
        return false;
    }
}

/************************************************************************/
/*			chk_comp_name_legal				*/
/* Check for legal characters in a component name.			*/
/* All characters must be legal MMS Identifier characters but not '$'.	*/
/* Allow only alphanumeric or '_'.					*/
/************************************************************************/
pub fn chk_comp_name_legal(input_str: &[u8]) -> crate::Result<()> {
    for e in input_str {
        if !(e.is_ascii_alphanumeric()) && (*e != b'_') {
            bail!("comname i legal");
        }
    }
    Ok(())
}

/************************************************************************/
/*			ascii_to_objid					*/
/* Convert string into Object Identifier.				*/
/************************************************************************/
pub fn ascii_to_objid(astr: &str) -> crate::Result<MmsObjId> {
    let mut objid = MmsObjId::default();

    let sp_str = astr.split_whitespace();
    for e in sp_str {
        if objid.num_comps >= MAX_OBJID_COMPONENTS as i32 {
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

/************************************************************************/
/*			ascii_to_hex_str				*/
/*  将asc字符 表示为 十六进制字符 */
/************************************************************************/

pub fn ascii_to_hex_str(
    //  ST_UCHAR *hstr,		/* hex string	 		*/
    //       ST_UINT *hlen_out,	/* ptr to hex len to be set	*/
    hlen_max: u32, /* 允许的最大 长度 maximum hex len to allow.	*/
    astr: &[u8],
) -> crate::Result<Vec<u8>> /* ascii string			*/
{
    let mut hstr = Vec::new();

    let mut nibble = false; /* SD_TRUE if nibble read, SD_FALSE if whole byte read*/
  
    let mut now_val: u8 = 0;
    for c in astr {
        if c.is_ascii_hexdigit() {
            if hstr.len() > hlen_max as usize {
                bail!("hstr already full. Can't add digit");
            }
            let  digit: u32 =if c.is_ascii_digit() {
               *c as u32 - b'0' as u32
            } else {
                 10 + c.to_ascii_uppercase() as u32 - b'A' as u32
            };
            if nibble {
                /* set low nibble	*/
                nibble = false;
                now_val |= digit as u8;
                hstr.push(now_val);
            } else {
                /* set high nibble	*/
                nibble = true;
                now_val = (digit << 4) as u8;
            }
        } else if c.is_ascii_whitespace() {
            continue;
        } else {
            bail!("ascii_to_hex_str pares err");
        }
    }
    return Ok(hstr);
}

#[derive(Default, Clone)]
pub struct SclOptions {
    pub forceedition: u32, /* 0 = use edition detected in SCL file	*/
    /* 1 = force Edition 1 parsing		*/
    /* 2 = force Edition 2 parsing		*/
    /* NOTE: "includeOwner" should NOT be used if Tissue 807 is approved.	*/
    /*       It should only be used as an alternative way to control	*/
    /*       inclusion of "Owner" until Tissue 807 is resolved.		*/
    pub includeowner: bool, /* control inclusion of "Owner" in RCBs.*/
}

#[derive(Default, Clone)]
pub struct SclHeader {
    /* NOTE: only required elements included here. Add optional elements as needed.*/
    // pub ST_CHAR id            [MAX_IDENT_LEN+1];
    pub id: String,
    /* Defined values for "namestructure" attribute	*/
    pub namestructure: u32,
}

#[derive(Debug, Clone)]
pub struct MmsObjId {
    pub num_comps: i32,                     /* number of objid components	*/
    pub comps: [i16; MAX_OBJID_COMPONENTS], /* identifier components	*/
}

impl Default for MmsObjId {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
/* This structure contains AE_TITLE info.				*/
#[derive(Default, Clone)]
pub struct AeTitle {
    pub ap_title_pres: bool,  /* present flag                 */
    pub ap_title: MmsObjId,   /* AP title                     */
    pub ae_qual_pres: bool,   /* present flag                 */
    pub ae_qual: i32,         /* AE qualifier                 */
    pub ap_inv_id_pres: bool, /* present flag                 */
    pub ap_inv_id: i32,       /* AP invocation ID             */
    pub ae_inv_id_pres: bool, /* present flag                 */
    pub ae_inv_id: i32,       /* AE invocation ID             */
}

#[derive(Default, Clone)]
pub struct SclGse {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    pub ldinst: String,  // [u8; MAX_IDENT_LEN + 1],
    pub cbname: String,  // [u8; MAX_IDENT_LEN + 1],
    pub mac: MacAddress, // [u8; CLNP_MAX_LEN_MAC], /* Multicast mac address	*/
    pub appid: u32,
    pub vlanpri: u32,
    pub vlanid: u32,
    pub mintime: u32, /* Minimum GOOSE retrans time (ms)	*/
    pub maxtime: u32, /* Maximum GOOSE retrans time (ms)	*/
}
#[derive(Default, Clone)]
pub struct SclSmv {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    // struct scl_smv *next;		/* CRITICAL: DON'T MOVE.	*/
    // struct scl_smv *prev;		/* CRITICAL: DON'T MOVE.	*/
    pub ldinst: String,  //[u8; MAX_IDENT_LEN + 1],
    pub cbname: String,  //[u8; MAX_IDENT_LEN + 1],
    pub mac: MacAddress, //[u8; CLNP_MAX_LEN_MAC], /* Multicast mac address	*/
    pub appid: u32,
    pub vlanpri: u32,
    pub vlanid: u32,
}

#[derive(Clone)]
pub struct SclAddress {
    /* NOTE: there is only one Address allowed, so this is never put on 	*/
    /* a linked list.							*/
    pub ae_title: AeTitle, /* includes AP title, AE qualifier, etc.	*/

    pub psel_len: u32,
    pub psel: [u8; MAX_PSEL_LEN],
    pub ssel_len: u32,
    pub ssel: [u8; MAX_SSEL_LEN],
    pub tsel_len: u32,
    pub tsel: [u8; MAX_TSEL_LEN],
    /*changed by cl  */
    //pub ip: u32, /* IP Addr (network byte order)	*/
    pub ip: Ipv4Addr,
}
impl Default for SclAddress {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
/* Data from "ConnectedAP" element	*/
#[derive(Default, Clone)]
pub struct SclCap {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    // ST_CHAR iedname[MAX_IDENT_LEN+1];
    pub iedname: String,
    // ST_CHAR *desc;		/* description (optional)*/
    pub desc: String,
    /* may be long so allocate if present*/
    //ST_CHAR apname[MAX_IDENT_LEN+1];
    pub apname: String,
    pub address: SclAddress,  /* one address. NO LINKED LIST.	*/
    pub gse_vec: Vec<SclGse>, /* head of list of GSE defs	*/
    pub smv_vec: Vec<SclSmv>, /* head of list of SMV defs	*/
}
/* Data from "Subnetwork" element	*/
#[derive(Default, Clone)]
pub struct SclSubnet {
    //ST_CHAR name[MAX_IDENT_LEN+1];
    pub name: String,
    //ST_CHAR *desc;		/* description (optional)*/
    /* may be long so allocate if present*/
    pub desc: String,
    //ST_CHAR type[MAX_IDENT_LEN+1];
    pub r#type: String,
    //  SCL_CAP *cap_vec;		/* head of list of ConnectedAP defs	*/
    pub cap_vec: Vec<SclCap>,
}
#[derive(Default, Debug, Clone)]
pub struct SclDo {
    pub name: String,   // [u8; MAX_IDENT_LEN + 1],   /* data object name		*/
    pub r#type: String, // [u8; MAX_IDENT_LEN + 1], /* data object type		*/
}
#[derive(Default, Debug, Clone)]
pub struct SclLntype {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    pub id: String, //[u8; MAX_IDENT_LEN + 1], /* name used to reference this LN Type*/
    pub lnclass: String, //[u8; MAX_IDENT_LEN + 1], /* logical node class		*/
    // Scl_do *do_vec;		/* head of list of DO	*/
    pub do_vec: Vec<SclDo>,
    /* scl_lntype_add_do adds to list	*/
    pub type_id: i32, /* Initialized by "scl2_datatype_create_all"*/
}
#[derive(Default, Debug, Clone)]
pub struct SclSgVal {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    //struct scl_sg_val *next;		/* CRITICAL: DON'T MOVE.	*/
    //struct scl_sg_val *prev;		/* CRITICAL: DON'T MOVE.	*/
    pub sgroup: u32, /* Setting Group for this val	*/
    pub val: String, // Vec<u8>, /* val text			*/
                     /* allocate appropriate size buffer*/
}

#[derive(Default, Debug, Clone)]
pub struct SclDa {
    pub objtype: u32, /* SCL_OBJTYPE_DA or SCL_OBJTYPE_SDO	*/
    pub name: String, //[u8; MAX_IDENT_LEN + 1], /* DA or SDO name		*/
    pub desc: String, // Vec<u8>,                 /* description (optional)*/
    /* may be long so allocate if present*/
    pub saddr: String,   //[u8; MAX_IDENT_LEN + 1], /* for DA only: DA saddr	*/
    pub btype: String,   //[u8; MAX_IDENT_LEN + 1], /* for DA only: DA bType	*/
    pub valkind: String, // [u8; MAX_VALKIND_LEN + 1], /* for DA only: Spec, Conf, RO, or Set	*/
    pub r#type: String,  //[u8; MAX_IDENT_LEN + 1], /* for DA: needed if bType="Struct" or "Enum"*/
    /* for SDO: required		*/
    pub count: u32, /* for DA only: num array entries*/
    pub fc: String, //[u8; MAX_FC_LEN + 1], /* for DA only: functional constraint	*/
    pub dchg: bool, /* for DA only: TrgOp (data change)	*/
    pub qchg: bool, /* for DA only: TrgOp (quality change)	*/
    pub dupd: bool, /* for DA only: TrgOp (data update)	*/

    /* The "Val" and "sGroup" parameters are only set if the SCL file contains the
     * optional "Val" element, in which case "scl_dotype_add_da_val" is called.
     */

    //ST_CHAR *val,				/* for DA only: attribute value text	*/
                      /* allocate appropriate size buffer*/
    pub val: String, //Vec<u8>,
    pub sgval_vec: Vec<SclSgVal>, /* for DA only: linked list of	*/
                     /* Setting Group initial values	*/
}
#[derive(Default, Debug, Clone)]
pub struct SclDotype {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    //struct scl_dotype *next;		/* CRITICAL: DON'T MOVE.	*/
    //struct scl_dotype *prev;		/* CRITICAL: DON'T MOVE.	*/
    pub id: String, //[u8; MAX_IDENT_LEN + 1], /* name used to reference this DO Type	*/
    pub cdc: String, // [u8; MAX_CDC_LEN + 1],  /* CDC name				*/
    pub da_vec: Vec<SclDa>,
    /* head of list of DA or SDO		*/
    /* scl_dotype_add_da OR			*/
    /* scl_dotype_add_sdo adds to list	*/
}

/* This structure should be allocated and filled in by the function	*/
/* "scl_datype_add_bda".						*/
#[derive(Default, Debug, Clone)]
pub struct SclBda {
    pub name: String, //[u8; MAX_IDENT_LEN + 1], /* data attribute name		*/
    //ST_CHAR *desc;			/* description (optional)*/
    pub desc: String, // Vec<u8>,
    /* may be long so allocate if present*/
    pub saddr: String,   //[u8; MAX_IDENT_LEN + 1], /* for DA only: DA saddr	*/
    pub btype: String,   // [u8; MAX_IDENT_LEN + 1], /* data attribute type		*/
    pub valkind: String, //[u8; MAX_VALKIND_LEN + 1], /* Spec, Conf, RO, or Set	*/
    pub r#type: String,  // [u8; MAX_IDENT_LEN + 1], /* only used if btype="Struct" or "Enum"*/
    pub count: u32,      /* for DA only: num array entries*/

    /* The "Val" and "sGroup" parameters are only set if the SCL file contains the
     * optional "Val" element, in which case "scl_datype_add_bda_val" is called.
     */
    //ST_CHAR *val;				/* attribute value text		*/
    /* allocate appropriate size buffer*/
    pub val: String, //Vec<u8>,
    pub sgval_vec: Vec<SclSgVal>, /* linked list of Setting Group	*/
                     /* initial values		*/
} /* Basic Data Attribute		*/

#[derive(Default, Debug, Clone)]
pub struct SclDatype {
    //DBL_LNK l;
    pub id: String, //[u8; MAX_IDENT_LEN + 1], /* name used to reference this DA Type*/
    pub bda_vec: Vec<SclBda>, /* head of list of BDA	*/
                    /* scl_datype_add_bda adds to list	*/
}

#[derive(Default, Debug, Clone)]
pub struct SclEnumval {
    pub ord: i32, /* ord attribute	*/
    /* If string fits in EnumValBuf, it is copied there & EnumVal is set	*/
    /* to point to it. Else, EnumVal is allocated & string is copied to it.*/
    pub enumval: String, /* EnumVal pointer		*/
                         // pub EnumValBuf: String,//[u8; MAX_IDENT_LEN + 1], /* EnumVal buffer		*/
}
#[derive(Default, Debug, Clone)]
pub struct SclEnumtype {
    pub id: String, //[u8; MAX_IDENT_LEN + 1], /* name used to reference this DA Type*/
    pub enumval_vec: Vec<SclEnumval>, /* head of list of EnumVal	*/
                    /* scl_enumtype_add_enumval adds to list*/
}

#[derive(Default, Clone)]
pub struct SclServOpt {
    /* Report configuration parameters.		*/
    pub reportscanratems: u32, /* Report scan rate (millisec)		*/
    pub brcb_bufsize: i32,     /* BRCB buffer size			*/
    /* Log configuration parameters.		*/
    pub logscanratems: u32, /* Log scan rate (millisec)		*/
    pub logmaxentries: u32, /* Max number of Log entries allowed	*/
}

#[derive(Default, Clone)]
pub struct SclDai {
    pub flattened: String, // [u8; MAX_FLAT_LEN + 1], /* flattened attribute name	*/
    /* constructed from "name" & "ix"*/
    /* from DOI, SDI, & DAI		*/
    pub val: String, /* attribute value text		*/
    /* allocate appropriate size buffer*/
    pub sgval_vec: Vec<SclSgVal>, /* linked list of Setting Group	*/
    /* initial values		*/
    pub saddr: String,   //[u8; MAX_IDENT_LEN + 1],     /* from DAI			*/
    pub valkind: String, // [u8; MAX_VALKIND_LEN + 1], /* from DAI			*/
}
#[derive(Default, Clone)]
pub struct SclFcda {
    pub domname: String, // [u8; MAX_IDENT_LEN + 1], /* domain name (constructed)	*/
    pub ldinst: String,  //[u8; MAX_IDENT_LEN + 1],
    pub prefix: String,  //[u8; MAX_IDENT_LEN + 1],
    pub lninst: String,  //[u8; MAX_IDENT_LEN + 1],
    pub lnclass: String, // [u8; MAX_IDENT_LEN + 1],
    pub doname: String,  // [u8; MAX_IDENT_LEN + 1],
    pub daname: String,  // [u8; MAX_IDENT_LEN + 1],
    pub fc: String,      //[u8; MAX_FC_LEN + 1], /* ST, MX, etc.			*/
    pub ix: String,      //[u8; 5 + 1],          /* array index (5 digits max)	*/
}

#[derive(Default, Clone)]
pub struct SclDataset {
    pub name: String, //[u8; MAX_IDENT_LEN + 1], /* dataset name		*/
    pub desc: String, // Vec<u8>,                 /* description (optional)*/
    /* may be long so allocate if present*/
    pub fcda_vec: Vec<SclFcda>, /* head of list of FCDA	*/
}
/* "scl_rcb_add" allocates this struct, fills it in,		*/
/* and adds it to the linked list "rcbHead" in SCL_LN.		*/
#[derive(Default, Debug, Clone)]
pub struct SclRcb {
    pub name: String, //[u8; MAX_IDENT_LEN + 1],
    pub desc: String, //Vec<u8>, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String, //[u8; MAX_IDENT_LEN + 1],
    pub intgpd: u32,
    pub rptid: String, //[u8; MVL61850_MAX_RPTID_LEN + 1],
    pub confrev: u32,
    pub buffered: bool, /* TRUE if this is buffered RCB	*/
    pub buftime: u32,
    pub trgops: [u8; 1], /* 8-bit bitstring			*/
    /* Boolean vals from SCL file		*/
    /* (dchg, qchg, dupd, & period)		*/
    /* used to set bits in trgops bitstring	*/
    pub optflds: [u8; 2], /* 9-bit bitstring			*/
    /* Boolean vals from SCL file		*/
    /* (seqNum, timeStamp, dataSet,		*/
    /* reasoncode, dataRef, bufOvfl,	*/
    /* entryID, configRef)			*/
    /* segmentation boolean is ignored	*/
    /* used to set bits in optflds bitstring*/
    pub maxclient: u32, /* value of "RptEnabled max" attr.	*/
} /* Report Control Block	*/

#[derive(Default, Debug, Clone)]
pub struct SclLcb {
    pub name: String, //[u8; MAX_IDENT_LEN + 1],
    pub desc: String, //Vec<u8>, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String, //[u8; MAX_IDENT_LEN + 1],
    pub intgpd: u32,
    pub logname: String, // [u8; MAX_IDENT_LEN + 1],
    pub logena: bool,
    pub reasoncode: bool,
    pub trgops: [u8; 1], /* 8-bit bitstring			*/
                         /* Boolean vals from SCL file		*/
                         /* (dchg, qchg, dupd, & period)		*/
                         /* used to set bits in trgops bitstring	*/
}

#[derive(Default, Debug, Clone)]
pub struct SclGcb {
    pub name: String, //[u8; MAX_IDENT_LEN + 1], /* Name name of CB. Used to construct*/
    /* GoCBRef or GsCBRef		*/
    pub desc: String, //Vec<u8>, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String, //[u8; MAX_IDENT_LEN + 1], /* for GOOSE only	*/
    /* used to construct GOOSE DatSet*/
    pub confrev: u32,  /* for GOOSE only	*/
    pub isgoose: bool, /* SD_TRUE if "GOOSE", SD_FALSE if "GSSE"*/
    pub appid: String, //[u8; MVL61850_MAX_RPTID_LEN + 1], /* for GOOSE only	*/
    /* maps to goiD in 61850-7-2	*/
    pub subscribed: bool, /* user subscribed to this GCB	*/
                          /* The SCL file may also contain one or more "IEDName" elements to	*/
                          /* indicate IEDs that should subscribe for GOOSE data. We have no	*/
                          /* way to use this information, so it is ignored.			*/
}

/************************************************************************/
/*			Sampled Value Control Block			*/
/* "scl_parse" allocates this struct and fills it in.			*/
/* "scl_svcb_add" adds it to the linked list "svcbHead" in SCL_LN.	*/
#[derive(Default, Debug, Clone)]
pub struct SclSvcb {
    pub name: String, //[u8; MAX_IDENT_LEN + 1],
    pub desc: String, // Vec<u8>, /* description (optional)*/
    /* may be long so allocate if present*/
    pub datset: String, // [u8; MAX_IDENT_LEN + 1],
    /* "smvid" big enough for Edition 2, but only 65 char allowed for Edition 1*/
    pub smvid: String, // [u8; MVL61850_MAX_OBJREF_LEN + 1],
    pub smprate: u32,
    pub nofasdu: u32,
    pub confrev: u32,
    pub multicast: bool,  /* TRUE if this is MsvCB		*/
    pub optflds: [u8; 1], /* 8-bit bitstring			*/
    /* Boolean vals from "SmvOpts" in SCL	*/
    /* (sampleRate, etc.)			*/
    /* used to set bits in this bitstring	*/
    pub securitypres: bool, /* SmvOpts security flag	*/
    pub datarefpres: bool,  /* SmvOpts dataRef flag		*/
    /* For edition 2 only	*/
    pub smpmod: i8, /* SmpPerPeriod, SmpPerSec, or SecPerSmp*/
                    /* converted to Enumerated value	*/
} /* Sampled Value Control Block	*/

#[derive(Default, Debug, Clone)]
pub struct SclSgcb {
    /* NOTE: no DBL_LNK here. Only 2 allowed so never put on a linked list.*/
    pub desc: String, // Vec<u8>, /* description (optional)		*/
    /* may be long so allocate if present	*/
    pub numofsgs: u32, /* mandatory	*/
    pub actsg: u32,    /* optional	*/
}
#[derive(Default, Debug, Clone)]
pub struct SclExtref {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    //struct scl_extref *next;		/* CRITICAL: DON'T MOVE.	*/
    //struct scl_extref *prev;		/* CRITICAL: DON'T MOVE.	*/
    /* NOTE: ALL ATTRIBUTES BELOW ARE OPTIONAL.			*/
    /* Pointers are first just to reduce structure padding.	*/
    pub desc: String, //Vec<u8>, /* description				*/
    /* may be long so allocate if present	*/
    pub intaddr: String, //Vec<u8>, /* internal address			*/
    /* may be long so allocate if present	*/
    /* Max lengths of these attributes set by SCL Schema.	*/
    pub iedname: String,     // [u8; MAX_IDENT_LEN + 1],
    pub ldinst: String,      //[u8; MAX_IDENT_LEN + 1],
    pub prefix: String,      //[u8; 11 + 1],
    pub lnclass: String,     // [u8; 5 + 1],
    pub lninst: String,      // [u8; 12 + 1],
    pub doname: String,      // [u8; MAX_IDENT_LEN + 1],
    pub daname: String,      // [u8; MAX_IDENT_LEN + 1],
    pub servicetype: String, //[u8; 6 + 1],
    pub srcldinst: String,   //[u8; MAX_IDENT_LEN + 1],
    pub srcprefix: String,   // [u8; 11 + 1],
    pub srclnclass: String,  // [u8; 5 + 1],
    pub srclninst: String,   // [u8; 12 + 1],
    pub srccbname: String,   //[u8; 32 + 1],
}

#[derive(Default, Clone)]
pub struct SclLn {
    pub varname: String, //[u8; MAX_IDENT_LEN + 1], /* variable name (constructed)	*/
    pub desc: String,    // Vec<u8>,                    /* description (optional)*/
    /* may be long so allocate if present*/
    pub lntype: String,  //[u8; MAX_IDENT_LEN + 1],  /* LN Type name		*/
    pub lnclass: String, //[u8; MAX_IDENT_LEN + 1], /* LN Class name	*/
    /* for LN0, must be "LLN0"	*/
    pub inst: String, //[u8; MAX_IDENT_LEN + 1], /* LN inst name			*/
    /* for LN0, must be "" (empty string)*/
    pub prefix: String, //[u8; MAX_IDENT_LEN + 1], /* LN prefix name	*/
    /* for LNO, ignored	*/
    pub dai_vec: Vec<SclDai>,         /* head of list of DAI	*/
    pub dataset_vec: Vec<SclDataset>, /* head of list of DataSet	*/
    pub rcb_vec: Vec<SclRcb>,         /* head of list of RCB (Report Control)	*/
    pub lcb_vec: Vec<SclLcb>,         /* head of list of LCB (Log Control)	*/
    pub gcb_vec: Vec<SclGcb>,         /* head of list of GCB (GOOSE Control)	*/
    pub svcb_vec: Vec<SclSvcb>,       /* head of list of SVCB (Sampled Value Control)*/
    pub sgcb: Box<SclSgcb>,           /* SGCB (Setting Group Control)(only 1 allowed)*/
    pub extref_vec: Vec<SclExtref>,   /* head of list of ExtRef (in Inputs)	*/
    /* NOTE: In LN or LN0: Inputs ignored		*/
    /* NOTE: In LN0: SCLControl ignored		*/
    pub type_id: i32, /* Initialized by "scl2_datatype_create_all"*/
                      //MVL_VAR_ASSOC *mvl_var_assoc;	/* MVL Variable Association created from LN info*/
} /* Logical Node (LN or LN0 in SCL)	*/

#[derive(Default, Clone)]
pub struct SclLd {
    pub domname: String, //[u8; MAX_IDENT_LEN + 1], /* domain name (constructed)	*/
    pub desc: String,    /* description (optional)*/
    /* may be long so allocate if present*/
    pub inst: String, // [u8; MAX_IDENT_LEN + 1], /* LD inst name		*/
    pub ln_vec: Vec<SclLn>, /* head of list of LN	*/
                      /* NOTE: AccessControl in LDevice is ignored	*/
} /* Logical Device (LDevice in SCL)*/

#[derive(Default, Clone)]
pub struct SclServiceWithMax {
    pub enabled: bool,
    pub max: u32,
}
#[derive(Default, Clone, Debug)]
pub struct SclReportsettings {
    /* These may be "Dyn", "Conf", or "Fix". No other values allowed.	*/
    // pub cbname: [u8; 4 + 1],
    // pub datset: [u8; 4 + 1],
    // pub rptid: [u8; 4 + 1],
    // pub optfields: [u8; 4 + 1],
    // pub buftime: [u8; 4 + 1],
    // pub trgOps: [u8; 4 + 1],
    // pub intgpd: [u8; 4 + 1],
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

#[derive(Default, Clone)]
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

#[derive(Default, Clone)]
pub struct SclServer {
    /* CRITICAL: First 2 parameters used to add this struct to linked	*/
    /* lists using list_add_last, etc.					*/
    // struct scl_server *next;		/* CRITICAL: DON'T MOVE.	*/
    //struct scl_server *prev;		/* CRITICAL: DON'T MOVE.	*/
    pub serv_opt: SclServOpt, /* options not configured by SCL	*/
    pub ld_vec: Vec<SclLd>,   /* head of list of LDevice defs		*/
    /* for this Server			*/
    pub iedname: String, // [u8; MAX_IDENT_LEN + 1], /* IED name for this Server	*/
    pub apname: String,  // [u8; MAX_IDENT_LEN + 1],  /* AccessPoint name for this Server*/
    // pub vmd_ctrl:MVL_VMD_CTRL,	/* VMD created for this Server		*/
    pub scl_services: SclServices, /* Info from "Services" section of SCL	*/
}

#[derive(Default, Clone)]
pub struct SclInfo {
    pub edition: u32,
    /* 0 (default) means Edition 1		*/
    /* 2 means Edition 2			*/
    /* Other editions not supported.	*/
    pub options: SclOptions, /* parser options passed by user	*/

    pub header: SclHeader, /* Info from "Header" section of SCL file*/

    /* SubNetwork definitions from (from Communication section)		*/
    pub subnet_vec: Vec<SclSubnet>, /* head of list of SubNetwork defs	*/

    /* Logical Node Type definitions (from DataTypeTemplates section)	*/
    pub lntype_vec: Vec<SclLntype>, /* head of list	of LNodeType defs	*/
    pub dotype_vec: Vec<SclDotype>, /* head of list of DOType defs		*/
    pub datype_vec: Vec<SclDatype>, /* head of list of DAType defs		*/
    pub enumtype_vec: Vec<SclEnumtype>, /* head of list of EnumType defs	*/

    /* Server definitions (from "Server" section)				*/
    pub server_vec: Vec<SclServer>, /* head of list of Server defs		*/

    pub datatype_create_done: bool, /* flag set by scl2_datatype_create_all*/
    pub ld_create_done: bool,       /* flag set by scl2_ld_create_all*/
}

pub async fn scl_parse_cid(
    xmlfilename: impl AsRef<Path>,
    iedname: &str,
    accesspointname: &str,
    options: Option<SclOptions>, /* miscellaneous parser options		*/
                                 /* may be NULL if no options needed	*/
) -> crate::Result<SclInfo> /* main struct where all SCL info stored*/
{
    if !chk_mms_ident_legal(iedname) {
        bail!(format!("Invalid IED name: {}", iedname))
    }

    let icdstr = fs::read_to_string(xmlfilename)
        .await
        .context("open icd file failed  {}")?;
    // let bytesRead=cfgData.len();
    let mut scldecctrl = SclDecCtrl::default();
    scldecctrl.iedname = iedname.to_string();
    scldecctrl.accesspointname = accesspointname.to_string();
    scldecctrl.accesspointfound = false;
    if let Some(inof) = options {
        scldecctrl.sclinfo.options = inof;
    }

    let mut reader = Reader::from_str(icdstr.as_str());
    reader.trim_text(true);

    //let mut txt = Vec::new();
    //let mut ctx=ICD_PARSE_CONTEXT;
    let scl_tb_index_vec = vec![0];

    let mut ctx = IcdParseContext2::init_data();
    ctx.scl_dec_ctrl = scldecctrl;

    ctx.sx_push(scl_tb_index_vec.clone());
    let mut buf = Vec::new();
    loop {
        if ctx.errcode != SD_SUCCESS && ctx.errcode != SX_ERR_CONVERT {
            bail!(format!("err happened when parse icd ,code {}", ctx.errcode));
        }
        match reader.read_event(&mut buf) {
            Ok(Event::Start(ref e)) => {
                let start_tag_info = get_start_tag_info(e, &reader)?;
                ctx.sx_startel_ement(start_tag_info);
                if e.unescape_and_decode(&reader).is_ok() {
                    // println!("tag name start {}", e.unescape_and_decode(&reader).unwrap());
                } else {
                    println!("err start         fffffffffffffffffffffffffff");
                }
            }
            Ok(Event::End(ref e)) => {
                let end_tag_info = get_end_tag_info(e, &reader)?;
                ctx.sx_end_element(end_tag_info);
            }
            Ok(Event::Empty(ref e)) => {
                let start_tag_info = get_start_tag_info(e, &reader)?;
                let end_tag_info = TagInfo {
                    tag: start_tag_info.tag.clone(),
                    atts: HashMap::new(),
                };
                ctx.sx_startel_ement(start_tag_info);
                ctx.sx_end_element(end_tag_info);
            }
            Ok(Event::Text(e)) => match e.unescape_and_decode(&reader) {
                Ok(txt) => {
                    ctx.op_entry_text = Some(txt);
                }
                Err(e) => {
                    println!("get txt info err {} ", e);
                    break;
                }
            },
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            Ok(Event::Eof) => break,
            _ => (),
        }
        buf.clear();
    }
    if ctx.errcode == 0 {
        return Ok((*ctx.scl_dec_ctrl.sclinfo).clone());
    } else {
        bail!("pare icd failed");
    }
}

/*检查 iedname 是否 合法 */
pub fn chk_mms_ident_legal(name: &str) -> bool {
    for pchar in name.chars() {
        if (!pchar.is_alphanumeric()) && pchar != '_' && pchar != '$' {
            return false;
        }
    }
    true
}

// add for rcb info parse
#[derive(Default, Debug, Clone)]
pub struct RcbSubData {
    pub rcb_optflds: [u8; 2], /*cl add for rcb optionfields only */
    pub max: u32,
}

pub struct SclDecCtrl {
    pub iedname: String,
    pub accesspointname: String,
    pub accesspointfound: bool, /* SD_TRUE if IED and AccessPoint found	*/
    pub iednamematched: bool,
    pub accesspointmatched: bool,
    pub sclinfo: Box<SclInfo>,
    scl_gse: Box<SclGse>, /* Used for "GSE" in "Communication" section	*/
    scl_smv: Box<SclSmv>, /* Used for "SMV" in "Communication" section	*/
    scl_ld: Vec<SclLd>,   /* Used for "LDevice"				*/
    scl_ln: Vec<SclLn>,   /* Used for "LN" (Logical Node)			*/
    scl_rcb: Vec<SclRcb>, /* alloc to store ReportControl info		*/
    scl_lcb: Vec<SclLcb>, /* alloc to store LogControl info		*/
    pub trgops: [u8; 1],  /* Used for ReportControl or LogControl.	*/
    pub rcb_sub_data: RcbSubData,
    /* Copied to SCL_RCB or SCL_LCB.		*/
    pub scl_svcb: Vec<SclSvcb>,       /* Used for "SampledValueControl".	*/
    pub scl_enumval: Vec<SclEnumval>, /* Used for "EnumVal".			*/
    pub scl_dai: Vec<SclDai>,         /* Used for "DAI".				*/
    pub scl_da: Vec<SclDa>,           /* Used for "DA".				*/
    pub scl_bda: Vec<SclBda>,         /* Used for "BDA".				*/
    pub flattened: String,            //[u8; MAX_FLAT_LEN + 1], /* Created by concatenating values*/
    /* from DOI, SDI, and DAI elements*/
    pub sgrouptmp: u32, /* temporary "sGroup" value: set when element	*/
    /* start proc'd, used when element end proc'd.	*/
    /* Parameters below used for special parsing modes.			*/
    pub parsemode: u32, /* one of "SCL_PARSE_MODE_*" defines.	*/
    /* Set by main parse functions.		*/
    pub iedtypematched: bool, /* SD_TRUE if iedType matches one requested*/
    /* used for LNodeType, DOType, DAType	*/
    pub iednameproc: String, /* iedname being processed	*/

    pub scl_services: SclServices, /* Info from "Services" section		*/
                                   /* Copied to SclServer when created.	*/
}
impl Default for SclDecCtrl {
    fn default() -> Self {
        //  unsafe { std::mem::zeroed() }
        SclDecCtrl {
            iedname: String::new(),
            accesspointname: String::new(),
            accesspointfound: false, /* SD_TRUE if IED and AccessPoint found	*/
            iednamematched: false,
            accesspointmatched: false,
            sclinfo: Box::new(SclInfo::default()),
            scl_gse: Box::new(SclGse::default()), /* Used for "GSE" in "Communication" section	*/
            scl_smv: Box::new(SclSmv::default()), /* Used for "SMV" in "Communication" section	*/
            scl_ld: Vec::new(),                   /* Used for "LDevice"				*/
            scl_ln: Vec::new(),                   /* Used for "LN" (Logical Node)			*/
            scl_rcb: Vec::new(),                  /* alloc to store ReportControl info		*/
            scl_lcb: Vec::new(),                  /* alloc to store LogControl info		*/
            trgops: [0; 1],                       /* Used for ReportControl or LogControl.	*/
            rcb_sub_data: RcbSubData::default(),
            /* Copied to SCL_RCB or SCL_LCB.		*/
            scl_svcb: Vec::new(),     /* Used for "SampledValueControl".	*/
            scl_enumval: Vec::new(),  /* Used for "EnumVal".			*/
            scl_dai: Vec::new(),      /* Used for "DAI".				*/
            scl_da: Vec::new(),       /* Used for "DA".				*/
            scl_bda: Vec::new(),      /* Used for "BDA".				*/
            flattened: String::new(), //[0; MAX_FLAT_LEN + 1], /* Created by concatenating values*/
            /* from DOI, SDI, and DAI elements*/
            sgrouptmp: 0, /* temporary "sGroup" value: set when element	*/
            /* start proc'd, used when element end proc'd.	*/
            /* Parameters below used for special parsing modes.			*/
            parsemode: 0, /* one of "SCL_PARSE_MODE_*" defines.	*/
            /* Set by main parse functions.		*/
            iedtypematched: false, /* SD_TRUE if iedType matches one requested*/
            /* used for LNodeType, DOType, DAType	*/
            iednameproc: String::new(), //[0; MAX_IDENT_LEN + 1], /* iedname being processed	*/

            scl_services: SclServices::default(), /* Info from "Services" section		*/
                                                  /* Copied to SclServer when created.	*/
        }
    }
}

pub struct SxElement {
    pub tag: String,
    pub elementflags: u32,
    pub funcptr: Box<dyn FnMut(&mut IcdParseContext2)>,
    // char *user;

    /* Runtime elements: */
    // ST_INT notUsed;
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
        tb.append(&mut gen_SubNetworkElements_tb());

        tb.append(&mut gen_ConnectedAPElements_tb());
        tb.append(&mut gen_AddressElements_tb());

        tb.append(&mut gen_GSEElements_tb());
        tb.append(&mut gen_GSEAddressElements_tb());
        tb.append(&mut gen_SMVElements_tb());
        tb.append(&mut gen_SMVAddressElements_tb());

        tb.append(&mut gen_AccessPointElements_tb());
        tb.append(&mut gen_ServerElements_tb());
        tb.append(&mut gen_LDeviceElements_tb());
        tb.append(&mut gen_LN0Elements_tb());
        tb.append(&mut gen_LNElements_tb());
        tb.append(&mut gen_DataSetElements_tb());
        tb.append(&mut gen_ReportControlElements_tb());
        tb.append(&mut gen_LogControlElements_tb());
        tb.append(&mut gen_SampledValueControlElements_tb());
        tb.append(&mut gen_InputsElements_tb());
        tb.append(&mut gen_DOIElements_tb());
        tb.append(&mut gen_SDIElements_tb());
        tb.append(&mut gen_DAIElements_tb());
        tb.append(&mut gen_LNodeTypeElements_tb());
        tb.append(&mut gen_DOTypeElements_tb());
        tb.append(&mut gen_DAElements_tb());
        tb.append(&mut gen_DATypeElements_tb());
        tb.append(&mut gen_BDAElements_tb());
        tb.append(&mut gen_EnumTypeElements_tb());
        tb.append(&mut gen_ServicesElements_tb());
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
    pub fn sx_startel_ement(&mut self, start_tag: TagInfo) {
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

    pub fn sx_end_element(&mut self, end_tag: TagInfo) {
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
                if self.items[last_index].numOccTbl[find_index] != 0
                    && ((elementflags & SX_ELF_RPT) == 0)
                {
                    self.errcode = SX_DUPLICATE_NOT_ALLOWED;
                    println!("Duplicate of element {} not allowed", tag);
                }
                self.items[last_index].numOccTbl[find_index] += 1;
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
            // SxElement *itemtbl;
            //存放的是 SxElement 的index
            itemtbl: itemtbl,
            numOccTbl: [0; SX_MAX_ITEMS_PER_TABLE],
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
                    "'forceedition' option used. Assuming 61850 Edition = {}",
                    sxdecctrl.scl_dec_ctrl.sclinfo.options.forceedition
                );
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.edition = 1;
                println!(
                    "Option forceedition = {} not supported. Assuming 61850 Edition 1",
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
            println!("header attribute namestructure={} not allowed. Assuming namestructure='IEDName' (i.e. 'Product Naming')", namestructure);
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
    

    if sxdecctrl.reason == SX_ELEMENT_START {
        /* start required attributes */
        let   required  = true;
        let op_name = sxdecctrl.scl_get_attr_ptr("name", required);
        if let Some(name) = op_name {
            if !chk_mms_ident_legal(&name) {
                println!("Illegal character in IED name {}'", name);
                sxdecctrl.errcode = SX_USER_ERROR;
                sxdecctrl.termflag = true;
                return;
            }
            /* Save to sclDecCtrl->iednameproc to use while processing this IED.*/
            // for (i,c) in name.as_bytes().iter().enumerate(){
            //     sxdecctrl.scl_dec_ctrl.iednameproc[i]=*c;
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

        if match_found {
            /* Initialize all default values in sclDecCtrl->scl_services.*/
            /* NOTE: Parsed values will be saved there. Later when SclServer	*/
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
        sxdecctrl.scl_dec_ctrl.iednameproc = String::new(); /* clear iedname. Done with this IED.*/
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
            scl_subnet.r#type = rtype;
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
        let op_iedName = sxdecctrl.scl_get_attr_ptr("iedName", SCL_ATTR_REQUIRED);
        if let Some(iedname) = op_iedName {
            scl_cap.iedname = iedname;
            //println!("ied name  att {}",scl_cap.iedname);
        } else {
            return;
        }

        let op_apname = sxdecctrl.scl_get_attr_ptr("apName", SCL_ATTR_REQUIRED);
        if let Some(apname) = op_apname {
            scl_cap.apname = apname;
            //println!("ied name  apname {}",scl_cap.apname);
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
        /*   "sclDecCtrl->sclinfo->subnet_vec->cap_vec->address".		*/
        //AddressElements
        sxdecctrl.sx_push(vec![16]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _address_p_sefun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_END {
        /* Save this Address element to appropriate member of this structure.*/
        //get last subnet_vec index
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
                    let res = ascii_to_hex_str(MAX_PSEL_LEN as u32, txt.as_bytes());
                    if let Ok(realvec) = res {
                        for (i, c) in realvec.iter().enumerate() {
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .address
                                .psel[i] = *c;
                        }

                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .psel_len = realvec.len() as u32;
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
                    let res = ascii_to_hex_str(MAX_SSEL_LEN as u32, txt.as_bytes());
                    if let Ok(realvec) = res {
                        for (i, c) in realvec.iter().enumerate() {
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .address
                                .ssel[i] = *c;
                        }

                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .ssel_len = realvec.len() as u32;
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
                    let res = ascii_to_hex_str(MAX_TSEL_LEN as u32, txt.as_bytes());
                    if let Ok(realvec) = res {
                        for (i, c) in realvec.iter().enumerate() {
                            sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                                [res_caplen - 1]
                                .address
                                .tsel[i] = *c;
                            // println!("tsel {}",*c);
                        }

                        sxdecctrl.scl_dec_ctrl.sclinfo.subnet_vec[sublen - 1].cap_vec
                            [res_caplen - 1]
                            .address
                            .tsel_len = realvec.len() as u32;
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
                    if let Ok(objid) = ascii_to_objid(txt.as_str()) {
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
                &sxdecctrl.scl_dec_ctrl.accesspointname.as_bytes(),
            ) {
                apname = name.clone();
                match_found = true;
            }
        } else {
            return;
        }

        /* Behavior depends on "parseMode".	*/

        if match_found {
            /* found caller structure with matching iedname/apname	*/
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
fn _LNodeType_SEFun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;
    //SclLntype *scl_lntype;

    let mut iedType = String::new(); //[MAX_IDENT_LEN+1];	/* optional iedType attr, if found*/
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Assume iedType matched. Clear this below if match not found.	*/
        sxdecctrl.scl_dec_ctrl.iedtypematched = true;

        /* IMPORTANT: For "SCD" parse mode, check the optional iedType,	*/
        /*            if present, BEFORE saving anything.			*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("iedType", required) {
            if txt.trim().len() > 0 {
                iedType = txt.trim().to_string();
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
fn _DOType_SEFun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut iedType = String::new(); //[MAX_IDENT_LEN+1];	/* optional iedType attr, if found*/
    if sxdecctrl.reason == SX_ELEMENT_START {
        /* Assume iedType matched. Clear this below if match not found.	*/
        sxdecctrl.scl_dec_ctrl.iedtypematched = true;

        /* IMPORTANT: For "SCD" parse mode, check the optional iedType,	*/
        /*            if present, BEFORE saving anything.			*/
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("iedType", required) {
            iedType = txt.trim().to_string();
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

fn _DAType_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
        //       sclDecCtrl->iedtypematched = SD_FALSE;	/* IGNORE THIS TYPE.	*/
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
fn _GSE_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            //   println!("gse ldinst {}",ldinst);

            scl_gse.ldinst = ldinst;
        } else {
            return;
        }
        let op_cbname = sxdecctrl.scl_get_attr_ptr("cbName", SCL_ATTR_REQUIRED);
        if let Some(cbname) = op_cbname {
            // println!("gse cb {}",cbname);

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
            //   println!("gse ldinst {}",ldinst);

            scl_smv.ldinst = ldinst;
        } else {
            return;
        }
        let op_cbname = sxdecctrl.scl_get_attr_ptr("cbName", SCL_ATTR_REQUIRED);
        if let Some(cbname) = op_cbname {
            // println!("gse cb {}",cbname);

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
            // println!("gse cb {}",cbname);
            if unit.trim() != "s" {
                println!("unit={} not allowed. Assuming unit='s'.", unit);
            }
        } else {
            return;
        }

        /* Check optional attribute.	*/
        let op_mul = sxdecctrl.scl_get_attr_ptr("multiplier", SCL_ATTR_OPTIONAL);
        if let Some(ref mul) = op_mul {
            // println!("gse cb {}",cbname);
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
fn _GSE_MaxTime_SEFun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        let op_unit = sxdecctrl.scl_get_attr_ptr("unit", SCL_ATTR_REQUIRED);
        if let Some(ref unit) = op_unit {
            // println!("gse cb {}",cbname);
            if unit.trim() != "s" {
                println!("unit={} not allowed. Assuming unit='s'.", unit);
            }
        } else {
            return;
        }

        /* Check optional attribute.	*/
        let op_mul = sxdecctrl.scl_get_attr_ptr("multiplier", SCL_ATTR_OPTIONAL);
        if let Some(ref mul) = op_mul {
            // println!("gse cb {}",cbname);
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
fn _GSE_Address_P_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
                            println!("pare vlanpri err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            // println!("VLANPRI  is {}",vlanpri);
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
                            println!("pare vlanid err {}", txt);
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
fn _SMV_Address_SEFun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //SMVAddressElements
        sxdecctrl.sx_push(vec![22]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _SMV_Address_P_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
                            println!("pare vlanpri err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            //  println!("VLANPRI  is {}",vlanpri);
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
                            println!("pare vlanid err {}", txt);
                            sxdecctrl.errcode = SX_USER_ERROR;
                            return;
                        } else {
                            //println!("VLANID  is {}", vlanid);
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
fn _Server_SEFun(sxdecctrl: &mut IcdParseContext2) {
    //println!("server fun exceeds");
    if sxdecctrl.reason == SX_ELEMENT_START {
        //ServerElements
        sxdecctrl.sx_push(vec![24]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _LDevice_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _LN_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            if let Err(er) = chk_comp_name_legal(scl_ln.inst.as_bytes()) {
                println!("ileegal com name {} ", scl_ln.inst);
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            }
        } else {
            return;
        }
        if let Some(txt) = sxdecctrl.scl_get_attr_ptr("lnClass", required) {
            scl_ln.lnclass = txt.trim().to_string();
            if let Err(er) = chk_comp_name_legal(scl_ln.lnclass.as_bytes()) {
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
                println! ("SCL PARSE: Attribute 'lnclass' of element 'LN0' has a value other then 'LLN0' (schema violation).");
                return;
            }
            // println!("ln class:{} inst {} prefix {} desc {} type {}",scl_ln.lnclass,scl_ln.inst,scl_ln.prefix,scl_ln.desc,scl_ln.lntype);

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
                "Illegal lnclass='{}'. Must be exactly 4 char",
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
                "Illegal definition for lnclass='{}': prefix ({}) plus inst (%s) > 11 char.",
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

fn _DataSet_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _ReportControl_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
                println!("rcb buftime parse faild  ");
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
            if let Err(er) = chk_comp_name_legal(scl_rcb.name.as_bytes()) {
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
                println!("rcb confrev parse faild  ");
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

        /* CRITICAL: Copy trgops to scl_rcb.	*/
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

fn _DOI_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _SampledValueControl_SEFun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        _SampledValueControl_SFun(sxdecctrl);
    } else {
        _SampledValueControl_EFun(sxdecctrl);
    }
}

/************************************************************************/
/*			_SampledValueControl_SFun			*/
/* Handle Start tag							*/
/************************************************************************/
fn _SampledValueControl_SFun(sxdecctrl: &mut IcdParseContext2) {
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

        if let Err(e) = chk_comp_name_legal(scl_svcb.name.as_bytes()) {
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
            println!("svcb smprate parse err");
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
            println!("svcb confrev parse err");
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
fn _SampledValueControl_EFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.sx_pop();
}
fn _LogControl_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            if let Err(e) = chk_comp_name_legal(scl_lcb.name.as_bytes()) {
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
        /* CRITICAL: Copy trgops to scl_lcb.	*/
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
fn _SettingControl_SFun(sxdecctrl: &mut IcdParseContext2) {
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

fn _GSEControl_SFun(sxdecctrl: &mut IcdParseContext2) {
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
        if let Err(e) = chk_comp_name_legal(scl_gcb.name.as_bytes()) {
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

fn _Inputs_SEFun(sxdecctrl: &mut IcdParseContext2) {
    if sxdecctrl.reason == SX_ELEMENT_START {
        //InputsElements
        sxdecctrl.sx_push(vec![47]);
    } else {
        sxdecctrl.sx_pop();
    }
}

fn _FCDA_SFun(sxdecctrl: &mut IcdParseContext2) {
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
    /* ASSUME namestructure="IEDName" (domain name = IED name + LDevice inst)*/
    /* namestructure="FuncName" is OBSOLETE.				*/

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
        // scl_fcda.ldinst, scl_fcda.prefix, scl_fcda.lninst,scl_fcda.lnclass, scl_fcda.doname,scl_fcda.daname,scl_fcda.fc);
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
fn _TrgOps_SFun(sxdecctrl: &mut IcdParseContext2) {
    // println!("now tripgs ");
    let mut required = false;

    sxdecctrl.scl_dec_ctrl.trgops = [0; 1]; /* Start with all bits=0	*/

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dchg", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(
                &mut sxdecctrl.scl_dec_ctrl.trgops[..],
                TRGOPS_BITNUM_DATA_CHANGE,
            );
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("qchg", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(
                &mut sxdecctrl.scl_dec_ctrl.trgops[..],
                TRGOPS_BITNUM_QUALITY_CHANGE,
            );
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dupd", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(
                &mut sxdecctrl.scl_dec_ctrl.trgops[..],
                TRGOPS_BITNUM_DATA_UPDATE,
            );
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("period", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(
                &mut sxdecctrl.scl_dec_ctrl.trgops[..],
                TRGOPS_BITNUM_INTEGRITY,
            );
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("gi", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(
                &mut sxdecctrl.scl_dec_ctrl.trgops[..],
                TRGOPS_BITNUM_GENERAL_INTERROGATION,
            );
        }
    } else {
        bstr_bit_set_on(
            &mut sxdecctrl.scl_dec_ctrl.trgops[..],
            TRGOPS_BITNUM_GENERAL_INTERROGATION,
        );
    }

    /* NOTE: "gi" defaults to "true".	*/

    /* end optional attributes */
}

fn _OptFlds_SFun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut optflds: [u8; 2] = [0; 2];

    /* start optional attributes */

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("seqNum", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_SQNUM);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("timeStamp", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_TIMESTAMP);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataSet", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_DATSETNAME);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("reasonCode", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_REASON);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataRef", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_DATAREF);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("bufOvfl", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_BUFOVFL);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("entryID", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_ENTRYID);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("configRef", required) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], OPTFLD_BITNUM_CONFREV);
        }
    }

    sxdecctrl.scl_dec_ctrl.rcb_sub_data.rcb_optflds = optflds;

    /* end optional attributes */
}

fn _RptEnabled_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _SmvOpts_SFun(sxdecctrl: &mut IcdParseContext2) {
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

    let mut optflds: [u8; 1] = [0; 1];
    let mut securityPres = false;
    let mut dataRefPres = false;

    /* start optional attributes */
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sampleRate", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_SMPRATE);
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("refreshTime", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_REFRTM);
        }
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("sampleSynchronized", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_SMPSYNCH);
        }
    }

    /* "sampleSynchronized" must be "true" for Edition 2.	*/
    if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2
        && !bstr_bit_get(&optflds[..], SVOPT_BITNUM_SMPSYNCH)
    {
        println! ("sampleSynchronized='false' not allowed for Edition 2. Automatically setting it to 'true'.");
        bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_SMPSYNCH);
    }

    /* "dataSet" is for Edition 2 only.	*/
    if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2 {
        if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataSet", SCL_ATTR_OPTIONAL) {
            if check_eq_2str_incaseinse(txt.trim(), "true") {
                bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_DATSET);
            }
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("security", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            securityPres = true;
            if sxdecctrl.scl_dec_ctrl.sclinfo.edition == 2 {
                bstr_bit_set_on(&mut optflds[..], SVOPT_BITNUM_SECURITY);
            }
        }
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("dataRef", SCL_ATTR_OPTIONAL) {
        if check_eq_2str_incaseinse(txt.trim(), "true") {
            dataRefPres = true;
        }
    }
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .optflds = optflds;

    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .securitypres = securityPres;
    sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
        [ln_len - 1]
        .svcb_vec[smv_len - 1]
        .datarefpres = dataRefPres;
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
fn _ExtRef_SFun(sxdecctrl: &mut IcdParseContext2) {
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

fn _SDI_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            let (t1, t2) = sxdecctrl.scl_dec_ctrl.flattened.split_at(index);
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

fn _DAI_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            let (t1, t2) = sxdecctrl.scl_dec_ctrl.flattened.split_at(index);
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
/* Sets "sclDecCtrl->scl_dai->val" OR adds entry to the linked list	*/
/* "sclDecCtrl->scl_dai->sgval_vec".					*/
/* NOTE: sclDecCtrl->sgrouptmp is set when reason == SX_ELEMENT_START	*/
/*       and used when reason == SX_ELEMENT_END.			*/
/************************************************************************/

fn _DAI_Val_SEFun(sxdecctrl: &mut IcdParseContext2) {
    //SCL_SG_VAL *scl_sg_val;

    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sgroup attr NOT present	*/
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
                /* sgroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store val*/
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1].ln_vec
                    [ln_len - 1]
                    .dai_vec[dai_len - 1]
                    .sgval_vec
                    .push(scl_sg_val);

            //scl_sg_val = scl_dai_sg_val_add (sclDecCtrl->scl_dai);
            } else if (sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                .ln_vec[ln_len - 1]
                .dai_vec[dai_len - 1]
                .val
                .len()
                > 0)
            {
                /* DO NOT allow multiple "Val" without "sGroup": pointer	*/
                /* sclDecCtrl->scl_dai->val would get overwritten, and never freed.*/
                println!("Multiple 'val' elements without 'sgroup' not allowed in DAI");
                sxdecctrl.errcode = SX_USER_ERROR;
                return;
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.server_vec[servr_len - 1].ld_vec[ld_len - 1]
                    .ln_vec[ln_len - 1]
                    .dai_vec[dai_len - 1]
                    .val = txt.trim().to_string();
            }
        } else {
            println!("Error parsing element 'val' of DAI");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _DO_SFun(sxdecctrl: &mut IcdParseContext2) {
    let mut required = false;

    let mut scl_do = SclDo::default();

    /* start required attributes */
    required = true;
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("name", required) {
        scl_do.name = txt.trim().to_string();
        if let Err(e) = chk_comp_name_legal(scl_do.name.as_bytes()) {
            println!("Illegal character in DO name '{}'", scl_do.name);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }
    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
        scl_do.r#type = txt.trim().to_string();
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

fn _DA_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            scl_da.r#type = txt.trim().to_string();
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
            if let Err(e) = chk_comp_name_legal(scl_da.name.as_bytes()) {
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
        //scl_da = sclDecCtrl->scl_da = scl_dotype_add_da (sclDecCtrl->sclinfo);
        //DAElements
        sxdecctrl.sx_push(vec![56]);
    } else {
        sxdecctrl.sx_pop();
    }
}
fn _SDO_SFun(sxdecctrl: &mut IcdParseContext2) {
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
        if let Err(err) = chk_comp_name_legal(scl_da.name.as_bytes()) {
            println!("Illegal character in SDO name '{}'", scl_da.name);
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    } else {
        return;
    }

    if let Some(ref txt) = sxdecctrl.scl_get_attr_ptr("type", required) {
        scl_da.r#type = txt.trim().to_string();
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
fn _DA_Val_SEFun(sxdecctrl: &mut IcdParseContext2) {
    //println!("da val  kkkkkkkkkkkkkkkkkkkk");
    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sgroup attr NOT present	*/
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
                /* sgroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store val*/
                sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1].da_vec[da_desc_len - 1]
                    .sgval_vec
                    .push(scl_sg_val);

            //scl_sg_val = scl_dai_sg_val_add (sclDecCtrl->scl_dai);
            } else {
                sxdecctrl.scl_dec_ctrl.sclinfo.dotype_vec[dotype_len - 1].da_vec[da_desc_len - 1]
                    .val = txt.trim().to_string();
            }
        } else {
            println!("Error parsing element 'val' of DA");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}

fn _BDA_SEFun(sxdecctrl: &mut IcdParseContext2) {
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
            scl_bda.r#type = txt.trim().to_string();
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
            if let Err(e) = chk_comp_name_legal(scl_bda.name.as_bytes()) {
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
fn _BDA_Val_SEFun(sxdecctrl: &mut IcdParseContext2) {
    //println!("fjjjjjjjjjjjjjjj");
    if sxdecctrl.reason == SX_ELEMENT_START {
        sxdecctrl.scl_dec_ctrl.sgrouptmp = 0; /* Default: sgroup attr NOT present	*/
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
                /* sgroup attr is present.	*/
                /* Add entry to linked list	*/
                let mut scl_sg_val = SclSgVal::default();
                scl_sg_val.sgroup = sxdecctrl.scl_dec_ctrl.sgrouptmp;
                scl_sg_val.val = txt.trim().to_string(); /* alloc & store val*/
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
            println!("Error parsing element 'val' of BDA");
            sxdecctrl.errcode = SX_USER_ERROR;
            return;
        }
    }
}
fn _EnumVal_SEFun(sxdecctrl: &mut IcdParseContext2) {
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

///辅助函数 用来解析icd tag 为拥有的strign

fn get_start_tag_info<'a, B: BufRead>(
    btstart: &BytesStart<'a>,
    reader: &Reader<B>,
) -> crate::Result<TagInfo> {
    let tag_name = btstart.name();
    let res = from_utf8(tag_name).map_err(quick_xml::Error::Utf8)?;

    let tag = res.to_string();
    let mut atts: HashMap<String, String> = HashMap::new();
    let atts_u8 = btstart.attributes();
    for att in atts_u8 {
        if att.is_err() {
            bail!(att.unwrap_err());
        }
        let att = att.unwrap();
        let value = att.unescape_and_decode_value(reader)?;
        let key = att.key;
        let key = from_utf8(key).map_err(quick_xml::Error::Utf8)?;
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
    reader: &Reader<B>,
) -> crate::Result<TagInfo> {
    let tag_name = btend.name();
    let res = from_utf8(tag_name).map_err(quick_xml::Error::Utf8)?;

    let tag = res.to_string();
    let atts: HashMap<String, String> = HashMap::new();

    Ok(TagInfo {
        tag: tag,
        atts: atts,
    })
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
    if (ixlen != 0) {
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

//解析出来的tag信息还是要转成utf8
pub struct TagInfo {
    pub tag: String,
    pub atts: HashMap<String, String>,
}
//生成scl 处理表  scl
fn gen_scl_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);
    tb.push(SxElement {
        tag: String::from("SCL"), /*INDEX 0 */
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_scl_sefun),
    });
    //{"SCL", 		SX_ELF_CSTARTEND,		_scl_sefun, NULL, 0}
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

// {"SubNetwork",      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_subnetwork_sefun, NULL, 0}

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
//   {"Services",		SX_ELF_CSTARTEND,		services_sefun, NULL, 0},
//   {"AccessPoint",      	SX_ELF_CSTARTEND|SX_ELF_RPT, 	_accesspoint_sefun, NULL, 0}
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
//   {"EnumType", 		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_enumtype_sefun, NULL, 0}
// };

//DataTypeTemplatesElements 子元素 处理表 DataTypeTemplatesElements/
fn gen_sub_datatypetemplate_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(4);
    tb.push(SxElement {
        tag: String::from("LNodeType"), /*INDEX 8*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_LNodeType_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DOType"), /*INDEX 9 */
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_DOType_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DAType"), /*INDEX 10*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DAType_SEFun),
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
//   {"ConnectedAP",      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_connectedap_sefun, NULL, 0}
// };
//SubNetworkElements 子元素 处理表 SCL/Communication/SubNetwork/
fn gen_SubNetworkElements_tb() -> Vec<SxElement> {
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
//   {"Address",		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_address_sefun, NULL, 0},
//   {"GSE",	      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_GSE_SEFun, NULL, 0},
//   {"SMV",	      	SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_smv_sefun, NULL, 0}
// };
//ConnectedAPElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements
fn gen_ConnectedAPElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(3);
    tb.push(SxElement {
        tag: String::from("Address"), /*INDEX 13*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_address_sefun),
    });
    tb.push(SxElement {
        tag: String::from("GSE"), /*INDEX 14*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_GSE_SEFun),
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
//   {"P",			SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_address_p_sefun, NULL, 0}
// };
//AddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/AddressElements
fn gen_AddressElements_tb() -> Vec<SxElement> {
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
//   {"Address",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_gse_address_sefun, NULL, 0},
//   {"MinTime",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_gse_mintime_sefun, NULL, 0},
//   {"MaxTime",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_GSE_MaxTime_SEFun, NULL, 0}
// };
//GSEElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/GSEElements
fn gen_GSEElements_tb() -> Vec<SxElement> {
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
        funcptr: Box::new(_GSE_MaxTime_SEFun),
    });

    return tb;
}

// SxElement GSEAddressElements[] =
// {
//   {"P",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_GSE_Address_P_SEFun, NULL, 0}
// };
//GSEAddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/GSEElements/GSEAddressElements
fn gen_GSEAddressElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("P"), /*INDEX 20*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_GSE_Address_P_SEFun),
    });

    return tb;
}

// SxElement SMVElements[] =
// {
//   {"Address",      	SX_ELF_CSTARTEND|SX_ELF_OPT, 	_SMV_Address_SEFun, NULL, 0}
// };
//SMVElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/SMVElements
fn gen_SMVElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Address"), /*INDEX 21*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPT,
        funcptr: Box::new(_SMV_Address_SEFun),
    });

    return tb;
}
// SxElement SMVAddressElements[] =
// {
//   {"P",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SMV_Address_P_SEFun, NULL, 0}
// };
//SMVAddressElements 子元素 处理表 SCL/Communication/SubNetwork/ConnectedAPElements/SMVElements/SMVAddressElements
fn gen_SMVAddressElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("P"), /*INDEX 22*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_SMV_Address_P_SEFun),
    });

    return tb;
}

// SxElement AccessPointElements[] =
// {
//   {"Server",      	SX_ELF_CSTARTEND, 		_Server_SEFun, NULL, 0}
// };
//Server 子元素 处理表 SCL/IED/Server、AccessPointElements
fn gen_AccessPointElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Server"), /*INDEX 23*/
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_Server_SEFun),
    });

    return tb;
}

// SxElement ServerElements[] =
// {
//   {"LDevice",      	SX_ELF_CSTARTEND|SX_ELF_RPT,	_LDevice_SEFun, NULL, 0}
// };
//ServerElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements
fn gen_ServerElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("LDevice"), /*INDEX 24*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_LDevice_SEFun),
    });

    return tb;
}

// SxElement LDeviceElements[] =
// {
//   {"LN0",      		SX_ELF_CSTARTEND,		_LN_SEFun, NULL, 0},
//   {"LN",      		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_LN_SEFun, NULL, 0}
// };
//LDeviceElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements
fn gen_LDeviceElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("LN0"), /*INDEX 25*/
        elementflags: SX_ELF_CSTARTEND,
        funcptr: Box::new(_LN_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("LN"), /*INDEX 26*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_LN_SEFun),
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
fn gen_LN0Elements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(8);

    tb.push(SxElement {
        tag: String::from("DataSet"), /*INDEX 27*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DataSet_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("ReportControl"), /*INDEX 28*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_ReportControl_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DOI"), /*INDEX 29*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DOI_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("SampledValueControl"), /*INDEX 30*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_SampledValueControl_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("LogControl"), /*INDEX 31*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_LogControl_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("SettingControl"), /*INDEX 32*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_SettingControl_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GSEControl"), /*INDEX 33*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_GSEControl_SFun),
    });
    tb.push(SxElement {
        tag: String::from("Inputs"), /*INDEX 34*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_Inputs_SEFun),
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
fn gen_LNElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(6);

    tb.push(SxElement {
        tag: String::from("DataSet"), /*INDEX 35*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DataSet_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("ReportControl"), /*INDEX 36*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_ReportControl_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DOI"), /*INDEX 37*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DOI_SEFun),
    });

    tb.push(SxElement {
        tag: String::from("SampledValueControl"), /*INDEX 38*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_SampledValueControl_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("LogControl"), /*INDEX 39*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_LogControl_SEFun),
    });

    tb.push(SxElement {
        tag: String::from("Inputs"), /*INDEX 40*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_Inputs_SEFun),
    });

    return tb;
}

// SxElement DataSetElements[] =
// {
//   {"FCDA",  		SX_ELF_CSTART|SX_ELF_RPT,	_FCDA_SFun, NULL, 0}
// };
//DataSetElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements、DataSetElements
fn gen_DataSetElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("FCDA"), /*INDEX 41*/
        elementflags: SX_ELF_CSTART | SX_ELF_RPT,
        funcptr: Box::new(_FCDA_SFun),
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
fn gen_ReportControlElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(3);

    tb.push(SxElement {
        tag: String::from("TrgOps"), /*INDEX 42*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_TrgOps_SFun),
    });
    tb.push(SxElement {
        tag: String::from("OptFields"), /*INDEX 43*/
        elementflags: SX_ELF_CSTART,
        funcptr: Box::new(_OptFlds_SFun),
    });
    tb.push(SxElement {
        tag: String::from("RptEnabled"), /*INDEX 44*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_RptEnabled_SFun),
    });

    return tb;
}

// SxElement LogControlElements[] =
// {
//   {"TrgOps",  		SX_ELF_CSTART|SX_ELF_OPT,	_TrgOps_SFun, NULL, 0}
// };
//LogControlElements 子元素 处理表 SCL/IED/Server、AccessPointElements/ServerElements/LDeviceElements/LNElements/LogControlElements
fn gen_LogControlElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("TrgOps"), /*INDEX 45*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_TrgOps_SFun),
    });

    return tb;
}

// SxElement SampledValueControlElements[] =
// {
//   {"SmvOpts",  		SX_ELF_CSTART,			_SmvOpts_SFun, NULL, 0}
// };
fn gen_SampledValueControlElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("SmvOpts"), /*INDEX 46*/
        elementflags: SX_ELF_CSTART,
        funcptr: Box::new(_SmvOpts_SFun),
    });

    return tb;
}

// SxElement InputsElements[] =
// {
// /* DEBUG: Text and Private elements ignored??	*/
//   {"ExtRef",  		SX_ELF_CSTART|SX_ELF_OPTRPT,	_ExtRef_SFun, NULL, 0}
// };
fn gen_InputsElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("ExtRef"), /*INDEX 47*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_ExtRef_SFun),
    });

    return tb;
}

// SxElement DOIElements[] =
// {
//   {"SDI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SDI_SEFun, NULL, 0},
//   {"DAI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_SEFun, NULL, 0}
// };
fn gen_DOIElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("SDI"), /*INDEX 48*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_SDI_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DAI"), /*INDEX 49*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DAI_SEFun),
    });

    return tb;
}

/* SDI can be nested under itself indefinitely */
// SxElement SDIElements[] =
// {
//   {"SDI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_SDI_SEFun, NULL, 0},
//   {"DAI",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_SEFun, NULL, 0}
// };
fn gen_SDIElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("SDI"), /*INDEX 50*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_SDI_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("DAI"), /*INDEX 51*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DAI_SEFun),
    });

    return tb;
}

// SxElement DAIElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DAI_Val_SEFun, NULL, 0}
// };

fn gen_DAIElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 52*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DAI_Val_SEFun),
    });

    return tb;
}

// SxElement LNodeTypeElements[] =
// {
//   {"DO",  		SX_ELF_CSTART|SX_ELF_RPT,	_DO_SFun, NULL, 0}
// };
fn gen_LNodeTypeElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("DO"), /*INDEX 53*/
        elementflags: SX_ELF_CSTART | SX_ELF_RPT,
        funcptr: Box::new(_DO_SFun),
    });

    return tb;
}

// SxElement DOTypeElements[] =
// {
//   {"DA",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DA_SEFun, NULL, 0},
//   {"SDO",  		SX_ELF_CSTART|SX_ELF_OPTRPT,	_SDO_SFun, NULL, 0}
// };

fn gen_DOTypeElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(2);

    tb.push(SxElement {
        tag: String::from("DA"), /*INDEX 54*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DA_SEFun),
    });
    tb.push(SxElement {
        tag: String::from("SDO"), /*INDEX 55*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPTRPT,
        funcptr: Box::new(_SDO_SFun),
    });

    return tb;
}

// SxElement DAElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_DA_Val_SEFun, NULL, 0}
// };
fn gen_DAElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 56*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_DA_Val_SEFun),
    });

    return tb;
}

// SxElement DATypeElements[] =
// {
//   {"BDA",  		SX_ELF_CSTARTEND|SX_ELF_RPT,	_BDA_SEFun, NULL, 0}
// };
fn gen_DATypeElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("BDA"), /*INDEX 57*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_BDA_SEFun),
    });

    return tb;
}

// SxElement BDAElements[] =
// {
//   {"Val",  		SX_ELF_CSTARTEND|SX_ELF_OPTRPT,	_BDA_Val_SEFun, NULL, 0}
// };

fn gen_BDAElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("Val"), /*INDEX 58*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_OPTRPT,
        funcptr: Box::new(_BDA_Val_SEFun),
    });

    return tb;
}

// SxElement EnumTypeElements[] =
// {
//   {"EnumVal",  		SX_ELF_CSTARTEND|SX_ELF_RPT,	_EnumVal_SEFun, NULL, 0}
// };

fn gen_EnumTypeElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(1);

    tb.push(SxElement {
        tag: String::from("EnumVal"), /*INDEX 59*/
        elementflags: SX_ELF_CSTARTEND | SX_ELF_RPT,
        funcptr: Box::new(_EnumVal_SEFun),
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
pub fn gen_ServicesElements_tb() -> Vec<SxElement> {
    let mut tb = Vec::with_capacity(19);

    tb.push(SxElement {
        tag: String::from("GetDirectory"), /*INDEX 60*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GetDirectory_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GetDataObjectDefinition"), /*INDEX 61*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GetDataObjectDefinition_SFun),
    });
    tb.push(SxElement {
        tag: String::from("DataObjectDirectory"), /*INDEX 62*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_DataObjectDirectory_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GetDataSetValue"), /*INDEX 63*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GetDataSetValue_SFun),
    });
    tb.push(SxElement {
        tag: String::from("SetDataSetValue"), /*INDEX 64*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_SetDataSetValue_SFun),
    });
    tb.push(SxElement {
        tag: String::from("DataSetDirectory"), /*INDEX 65*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_DataSetDirectory_SFun),
    });
    tb.push(SxElement {
        tag: String::from("ReadWrite"), /*INDEX 66*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_ReadWrite_SFun),
    });

    tb.push(SxElement {
        tag: String::from("TimerActivatedControl"), /*INDEX 67*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_TimerActivatedControl_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GetCBValues"), /*INDEX 68*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GetCBValues_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GSEDir"), /*INDEX 69*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GSEDir_SFun),
    });
    tb.push(SxElement {
        tag: String::from("FileHandling"), /*INDEX 70*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_FileHandling_SFun),
    });
    tb.push(SxElement {
        tag: String::from("ConfLdName"), /*INDEX 71*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_ConfLdName_SFun),
    });

    //   /* These entries for "tServiceWithMax".	*/
    tb.push(SxElement {
        tag: String::from("ConfLogControl"), /*INDEX 72*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_ConfLogControl_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GOOSE"), /*INDEX 73*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GOOSE_SFun),
    });
    tb.push(SxElement {
        tag: String::from("GSSE"), /*INDEX 74*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_GSSE_SFun),
    });
    tb.push(SxElement {
        tag: String::from("SMVsc"), /*INDEX 75*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_SMVsc_SFun),
    });
    tb.push(SxElement {
        tag: String::from("SupSubscription"), /*INDEX 76*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_SupSubscription_SFun),
    });
    tb.push(SxElement {
        tag: String::from("ConfSigRef"), /*INDEX 77*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_ConfSigRef_SFun),
    });

    //   /* More complex entries.	*/
    //   /* DEBUG: TO DO: Add entries for DynAssociation, SettingGroups, ConfDataSet,*/
    //   /*        DynDataSet, LogSettings, GSESettings, SMVSettings, ConfLNs.*/
    tb.push(SxElement {
        tag: String::from("ReportSettings"), /*INDEX 78*/
        elementflags: SX_ELF_CSTART | SX_ELF_OPT,
        funcptr: Box::new(_ReportSettings_SFun),
    });

    return tb;
}

//每一层 的元素表 信息  以及对应出现的次数
pub struct SxElementTblCtrl2 {
    //ST_INT numItems;
    // SxElement *itemtbl;
    //存放的是 SxElement 的index
    pub itemtbl: Vec<usize>,
    pub numOccTbl: [u32; SX_MAX_ITEMS_PER_TABLE],
}

pub fn scl_services_init(scl_services: &mut SclServices) {
    /*NOTE: This memset initializes all boolean members to 0 (SD_FALSE).	*/
    // memset (scl_services, 0, sizeof (SCL_SERVICES));
    *scl_services = SclServices::default();
    //     let fix=b"Fix";
    //    for i in 0..3{
    //     scl_services.ReportSettings.cbname[i]=fix[i];
    //     scl_services.ReportSettings.datset[i]=fix[i];
    //     scl_services.ReportSettings.rptid[i]=fix[i];
    //     scl_services.ReportSettings.optfields[i]=fix[i];
    //     scl_services.ReportSettings.buftime[i]=fix[i];
    //     scl_services.ReportSettings.trgOps[i]=fix[i];
    //     scl_services.ReportSettings.intgpd[i]=fix[i];
    //    }
    scl_services.reportsettings.cbname = String::from("Fix");
    scl_services.reportsettings.datset = String::from("Fix");
    scl_services.reportsettings.rptid = String::from("Fix");
    scl_services.reportsettings.optfields = String::from("Fix");
    scl_services.reportsettings.buftime = String::from("Fix");
    scl_services.reportsettings.trgops = String::from("Fix");
    scl_services.reportsettings.intgpd = String::from("Fix");
}
/************************************************************************/
/*			_GetDirectory_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _GetDirectory_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdirectory = true;
    //println!("get directly serei true  1");
}
/************************************************************************/
/*			_GetDataObjectDefinition_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _GetDataObjectDefinition_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdataobjectdefinition = true;
    //println!("get directly serei true  2");
}
/************************************************************************/
/*			_DataObjectDirectory_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _DataObjectDirectory_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.dataobjectdirectory = true;
    //println!("get directly serei true  3");
}
/************************************************************************/
/*			_GetDataSetValue_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _GetDataSetValue_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getdatasetvalue = true;
    //println!("get directly serei true  4");
}
/************************************************************************/
/*			_SetDataSetValue_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _SetDataSetValue_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.setdatasetvalue = true;
    //println!("get directly serei true  5");
}
/************************************************************************/
/*			_DataSetDirectory_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _DataSetDirectory_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.datasetdirectory = true;
    //println!("get directly serei true  6");
}
/************************************************************************/
/*			_ReadWrite_SFun					*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _ReadWrite_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.readwrite = true;
    //println!("get directly serei true  7");
}
/************************************************************************/
/*			_TimerActivatedControl_SFun			*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _TimerActivatedControl_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.timeractivatedcontrol = true;
    //println!("get directly serei true  8");
}
/************************************************************************/
/*			_GetCBValues_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _GetCBValues_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.getcbvalues = true;
    //println!("get directly serei true  9");
}
/************************************************************************/
/*			_GSEDir_SFun					*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _GSEDir_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.gsedir = true;
    //println!("get directly serei true  10");
}
/************************************************************************/
/*			_FileHandling_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _FileHandling_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.filehandling = true;
    //println!("get directly serei true  11");
}
/************************************************************************/
/*			_ConfLdName_SFun				*/
/* Just set boolean flag if this is found.				*/
/************************************************************************/
fn _ConfLdName_SFun(sxdecctrl: &mut IcdParseContext2) {
    sxdecctrl.scl_dec_ctrl.scl_services.confldname = true;
    //println!("get directly serei true  12");
}

/************************************************************************/
/*			_ConfLogControl_SFun				*/
/* Fill in structure.							*/
/************************************************************************/
fn _ConfLogControl_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _GOOSE_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _GSSE_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _SMVsc_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _SupSubscription_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _ConfSigRef_SFun(sxdecctrl: &mut IcdParseContext2) {
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
fn _ReportSettings_SFun(sxdecctrl: &mut IcdParseContext2) {
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
