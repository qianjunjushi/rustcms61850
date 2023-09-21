use crate::comdata;
use anyhow::{bail, Result};

//存放一些辅助函数

/***************************************/
/***********  目录       Start ******************/
/***************************************/
/*1 字符串处理函数     */
/*2 位操作     */

/***************************************/
/*********** 目录        End ******************/
/***************************************/

/*******************************************/
/***************************************/
/***********1 字符串处理函数          Start ******************/
/***************************************/

/***************************************/
/* asc字符串转化为hex字符串    */
/* "This is an example."      */
/*  转换结果 0x746869732069732061206578616d706c65   */
/***************************************/
pub fn ascii_to_hex(input: &str) -> Result<String> {
    let mut hex_str = String::new();
    for c in input.chars() {
        if c.is_ascii() {
            hex_str.push_str(&format!("{:02x}", c as u32));
        } else {
            bail!(format!("Error: ascii_to_hex failed {}", input));
        }
    }
    Ok(hex_str)
}

use std::{rc, str::FromStr};
/***************************************/
/*  hex 字符串转成 asc 码 字符串   */
/*  比如 54686973206973202061206578616d706c65 转成 this is  a exmaple   */
/*   注意有可能存在不是偶数个 会忽略最后孤单的人  */
/***************************************/
pub fn hex_to_ascii(hex_str: &str) -> Result<String> {
    let mut result = String::with_capacity(128);

    let mut chars = hex_str.chars();
    while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
        let byte = match u8::from_str_radix(&(a.to_string() + &b.to_string()), 16) {
            Ok(byte) => byte,
            Err(e) => bail!(format!("Error: hex_to_ascii failed {} {}", hex_str, e)),
        };
        result.push(byte as char);
    }

    Ok(result)
}
/***************************************/
/***********1 字符串处理函数          End ******************/
/***************************************/

/***************************************/
/*********** 位操作        Start ******************/
/***************************************/

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
// #define BSTR_BIT_SET_OFF(ptr,bitnum) \
// 	( ((ST_UINT8 *)(ptr))[(bitnum)/8] &= ~(0x80>>((bitnum)&7)) )

// /* BSTR_BIT_GET returns 0 if bit is clear, 1 if bit is set.	*/
// #define BSTR_BIT_GET(ptr,bitnum) \
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

/***************************************/
/***********位操作         End ******************/
/***************************************/
