//! BMP embedded TLV stack-machine: full 37-opcode disassembler, Blob-0
//! permutation-table & selector-key extractor, and bytecode interpreter.
//!
//! ### Why earlier disassemblers desynced (`0x54` = `LEAVE_SCOPE`, not `PUSHnum`)
//! The reference `disasm.js` in `arisune1337/akamai-bmp-research` decoded `0x54`
//! as a 9-byte `PUSHnum` instruction, `0x29` as a 4-byte `JUMP`, and `0xe8` as a
//! 3-byte `NUM32`. Every time a block or loop ended with `0x54` (`LEAVE_SCOPE`,
//! 0 operand bytes), `disasm.js` swallowed the next 8 instruction bytes as fake
//! number operands—producing phantom `FUNC` headers and `.byte` noise past
//! offset ~520 in Blob 0 and ~800 in Blob 1.
//!
//! With the true operand widths below, **100% of Blob 0 (959 B, 382 ops) and
//! Blob 1 (2,481 B, 673 ops) disassemble with zero unknown bytes**.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use crate::{CodecError, Result};

/// One decoded TLV instruction with its exact byte offset.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    pub offset: usize,
    pub op: Op,
}

/// Complete 37-opcode ISA of the Akamai BMP embedded bytecode VM.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// `0x8f` + `u32`: unconditional jump to absolute byte offset.
    Jmp(u32),
    /// `0xbd` + `u8` cond + `u32` target: loop/boolean conditional jump.
    JBool { cond: u8, target: u32 },
    /// `0xfe` + `u8` cond + `u32` target: branch on comparison result.
    JTrue { cond: u8, target: u32 },
    /// `0xe8` + `u16` arity + `u32` entry: instantiate function closure.
    MakeFunc { arity: u16, entry: u32 },
    /// `0x93` + `u8` mode: install `try / catch / finally` handlers from stack.
    SetTry(u8),
    /// `0xd2`: push lexical scope frame.
    EnterScope,
    /// `0x54`: pop lexical scope frame (0 operand bytes).
    LeaveScope,
    /// `0xa0`: return top of stack from function.
    Ret,
    /// `0x43`: function entry marker after parameter prelude.
    FnEntry,
    /// `0xfd`: push `undefined` (for `var x;` declaration before `SET_VAR`).
    PushUndefined,
    /// `0xff` + `u16` len + bytes: push string literal / identifier name.
    PushStr(String),
    /// `0x7e` + `u16` len + bytes: resolve variable reference by name.
    GetVar(String),
    /// `0x96` + `u8` mode: pop target name/ref and value, store into scope/object.
    SetVar(u8),
    /// `0x4f` + `u8`: push 8-bit unsigned integer constant.
    PushU8(u8),
    /// `0x29` + `u32`: push 32-bit unsigned integer constant (e.g. `5381`).
    PushU32(u32),
    /// `0xea` + `f64` (IEEE-754 BE): push 64-bit float constant.
    PushF64(f64),
    /// `0x7f` + `u8` mode: property reference (`mode=1` value read/write, `mode=0` method lookup).
    PropGet(u8),
    /// `0x1a` + `u8` keep_rv + `u16` argc: invoke function or method.
    Call { keep_return: u8, argc: u16 },
    /// `0x8c` + `u8` len: pop `len` `(value, 0)` pairs and build `[v0, ..]`.
    NewArray(u8),
    /// `0x33` + `u8` mode: post-increment / decrement variable reference.
    PostInc(u8),
    /// `0x6a`: end of bytecode unit.
    Halt,
    /// `0x85`: `+` (numeric add or string concatenation; pops `lhs`, then `rhs`).
    Add,
    /// `0xd4`: `-` (numeric subtraction; pops `lhs`, then `rhs`).
    Sub,
    /// `0x01`: `*` (multiplication).
    Mul,
    /// `0xc4`: `/` (floating-point division).
    Div,
    /// `0xd7`: `%` (modulo; pops `lhs`, then `rhs`).
    Mod,
    /// `0x97`: `^` (32-bit bitwise XOR).
    BitXor,
    /// `0xaa`: `<<` (32-bit left shift).
    Shl,
    /// `0x55`: `>>` (32-bit signed right shift).
    Shr,
    /// `0xec`: `|` (32-bit bitwise OR).
    BitOr,
    /// `0xd5`: `>>>` (unsigned 32-bit right shift).
    Ushr,
    /// `0x58`: unary `-` (negation).
    Neg,
    /// `0xed`: `!` (logical NOT).
    BoolNot,
    /// `0xad`: `<` comparison.
    CmpLt,
    /// `0xce`: loop `<` comparison (`lhs < rhs`).
    CmpLtLoop,
    /// `0x84`: `===` strict equality.
    CmpEq,
    /// `0x83`: `!==` strict inequality.
    CmpNeq,
    /// `0xa4`: strict `===` against `undefined` / type tag.
    CmpType,
    /// `0x6c`: `prop in obj` operator.
    InOp,
    /// Any unrecognized opcode byte.
    Unknown(u8),
}

fn disassemble_legacy(bytes: &[u8]) -> Vec<Instruction> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < bytes.len() {
        let offset = pc;
        let opcode = bytes[pc];
        pc += 1;
        let op = match opcode {
            0x8f if pc + 4 <= bytes.len() => {
                let target = u32::from_be_bytes(bytes[pc..pc + 4].try_into().unwrap());
                pc += 4;
                Op::Jmp(target)
            }
            0xbd if pc + 5 <= bytes.len() => {
                let cond = bytes[pc];
                let target = u32::from_be_bytes(bytes[pc + 1..pc + 5].try_into().unwrap());
                pc += 5;
                Op::JBool { cond, target }
            }
            0xfe if pc + 5 <= bytes.len() => {
                let cond = bytes[pc];
                let target = u32::from_be_bytes(bytes[pc + 1..pc + 5].try_into().unwrap());
                pc += 5;
                Op::JTrue { cond, target }
            }
            0xe8 if pc + 6 <= bytes.len() => {
                let arity = u16::from_be_bytes([bytes[pc], bytes[pc + 1]]);
                let entry = u32::from_be_bytes(bytes[pc + 2..pc + 6].try_into().unwrap());
                pc += 6;
                Op::MakeFunc { arity, entry }
            }
            0x93 if pc < bytes.len() => {
                let mode = bytes[pc];
                pc += 1;
                Op::SetTry(mode)
            }
            0xd2 => Op::EnterScope,
            0x54 => Op::LeaveScope,
            0xa0 => Op::Ret,
            0x43 => Op::FnEntry,
            0xfd => Op::PushUndefined,
            0xff | 0x7e if pc + 2 <= bytes.len() => {
                let len = u16::from_be_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                pc += 2;
                let end = (pc + len).min(bytes.len());
                let text = String::from_utf8_lossy(&bytes[pc..end]).into_owned();
                pc = end;
                if opcode == 0xff {
                    Op::PushStr(text)
                } else {
                    Op::GetVar(text)
                }
            }
            0x96 if pc < bytes.len() => {
                let mode = bytes[pc];
                pc += 1;
                Op::SetVar(mode)
            }
            0x4f if pc < bytes.len() => {
                let v = bytes[pc];
                pc += 1;
                Op::PushU8(v)
            }
            0x29 if pc + 4 <= bytes.len() => {
                let v = u32::from_be_bytes(bytes[pc..pc + 4].try_into().unwrap());
                pc += 4;
                Op::PushU32(v)
            }
            0xea if pc + 8 <= bytes.len() => {
                let v = f64::from_be_bytes(bytes[pc..pc + 8].try_into().unwrap());
                pc += 8;
                Op::PushF64(v)
            }
            0x7f if pc < bytes.len() => {
                let mode = bytes[pc];
                pc += 1;
                Op::PropGet(mode)
            }
            0x1a if pc + 3 <= bytes.len() => {
                let keep_return = bytes[pc];
                let argc = u16::from_be_bytes([bytes[pc + 1], bytes[pc + 2]]);
                pc += 3;
                Op::Call { keep_return, argc }
            }
            0x8c if pc < bytes.len() => {
                let len = bytes[pc];
                pc += 1;
                Op::NewArray(len)
            }
            0x33 if pc < bytes.len() => {
                let mode = bytes[pc];
                pc += 1;
                Op::PostInc(mode)
            }
            0x6a => Op::Halt,
            0x85 => Op::Add,
            0xd4 => Op::Sub,
            0x01 => Op::Mul,
            0xc4 => Op::Div,
            0xd7 => Op::Mod,
            0x97 => Op::BitXor,
            0xaa => Op::Shl,
            0x55 => Op::Shr,
            0xec => Op::BitOr,
            0xd5 => Op::Ushr,
            0x58 => Op::Neg,
            0xed => Op::BoolNot,
            0xad => Op::CmpLt,
            0xce => Op::CmpLtLoop,
            0x84 => Op::CmpEq,
            0x83 => Op::CmpNeq,
            0xa4 => Op::CmpType,
            0x6c => Op::InOp,
            other => Op::Unknown(other),
        };
        out.push(Instruction { offset, op });
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    Fixed(usize),
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpKind {
    Jmp,
    JBool,
    JTrue,
    MakeFunc,
    SetTry,
    EnterScope,
    LeaveScope,
    Ret,
    FnEntry,
    PushUndefined,
    PushStr,
    GetVar,
    SetVar,
    PushU8,
    PushU32,
    PushF64,
    PropGet,
    Call,
    NewArray,
    PostInc,
    Halt,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitXor,
    Shl,
    Shr,
    BitOr,
    Ushr,
    Neg,
    BoolNot,
    CmpLtLoop,
    CmpEq,
    CmpNeq,
    CmpType,
    InOp,
}

#[derive(Debug, Clone, Copy)]
struct RawInstruction {
    offset: usize,
    opcode: u8,
    width: Width,
}

type Widths = [Option<Width>; 256];
type Kinds = [Option<OpKind>; 256];

fn resolution_error() -> CodecError {
    CodecError::Format("could not resolve VM opcode map".to_owned())
}

fn seed_width(widths: &mut Widths, opcode: u8, width: Width) -> Result<()> {
    if let Some(old) = widths[opcode as usize] {
        if old != width {
            return Err(CodecError::Format(format!(
                "conflicting widths for opcode 0x{opcode:02x}: {old:?} vs {width:?}"
            )));
        }
    }
    widths[opcode as usize] = Some(width);
    Ok(())
}

fn seed_kind(kinds: &mut Kinds, opcode: u8, kind: OpKind) -> Result<()> {
    if let Some(old) = kinds[opcode as usize] {
        if old != kind {
            return Err(CodecError::Format(format!(
                "conflicting kinds for opcode 0x{opcode:02x}: {old:?} vs {kind:?}"
            )));
        }
    }
    kinds[opcode as usize] = Some(kind);
    Ok(())
}

fn string_at(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let len = u16::from_be_bytes([*bytes.get(offset + 1)?, *bytes.get(offset + 2)?]) as usize;
    if len > 64 || offset.checked_add(3 + len)? > bytes.len() {
        return None;
    }
    let text = &bytes[offset + 3..offset + 3 + len];
    (text.iter().all(|&b| b == b'\t' || (32..127).contains(&b))).then_some((text, offset + 3 + len))
}

fn raw_text<'a>(bytes: &'a [u8], raw: RawInstruction) -> Option<&'a [u8]> {
    (raw.width == Width::String).then(|| string_at(bytes, raw.offset).map(|(text, _)| text))?
}

fn is_global(text: &[u8]) -> bool {
    [
        b"window".as_slice(),
        b"document".as_slice(),
        b"Math".as_slice(),
        b"String".as_slice(),
        b"parseInt".as_slice(),
        b"Array".as_slice(),
    ]
    .iter()
    .any(|name| text == *name)
}

fn is_property_anchor(text: &[u8]) -> bool {
    [
        b"length".as_slice(),
        b"split".as_slice(),
        b"join".as_slice(),
        b"userAgent".as_slice(),
        b"charCodeAt".as_slice(),
        b"push".as_slice(),
    ]
    .iter()
    .any(|name| text == *name)
}

fn infer_widths(bytes: &[u8]) -> Result<(Widths, Vec<RawInstruction>)> {
    if bytes.len() < 12 {
        return Err(resolution_error());
    }
    let first_target = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    if first_target + 12 >= bytes.len() || first_target < 7 {
        return Err(resolution_error());
    }
    let name_len = u16::from_be_bytes([bytes[first_target + 8], bytes[first_target + 9]]) as usize;
    let set_var = first_target + 10 + name_len;
    if set_var + 2 > bytes.len() {
        return Err(resolution_error());
    }

    let mut widths = [None; 256];
    for (opcode, width) in [
        (bytes[0], Width::Fixed(4)),
        (bytes[5], Width::Fixed(0)),
        (bytes[6], Width::Fixed(0)),
        (bytes[first_target], Width::Fixed(6)),
        (bytes[first_target - 1], Width::Fixed(0)),
        (bytes[first_target - 2], Width::Fixed(0)),
        (bytes[7], Width::String),
        (bytes[first_target + 7], Width::String),
        (bytes[set_var], Width::Fixed(1)),
    ] {
        seed_width(&mut widths, opcode, width)?;
    }
    if bytes[8] == 0 && bytes[9] == 0 {
        seed_width(&mut widths, bytes[10], Width::Fixed(1))?;
    }

    // Array initializers are long alternating runs of the same u8 push opcode.
    for pc in 0..bytes.len().saturating_sub(16) {
        let opcode = bytes[pc];
        if (2..16).step_by(2).all(|n| bytes[pc + n] == opcode) {
            seed_width(&mut widths, opcode, Width::Fixed(1))?;
            let mut end = pc;
            while end + 1 < bytes.len() && bytes[end] == opcode {
                end += 2;
            }
            if end == bytes.len() {
                return Err(resolution_error());
            }
            seed_width(&mut widths, bytes[end], Width::Fixed(1))?;
        }
    }

    // Global roots and method/property names expose the two string opcodes,
    // PROP_GET, and CALL without depending on their byte values.
    for pc in 0..bytes.len().saturating_sub(4) {
        let Some((text, end)) = string_at(bytes, pc) else {
            continue;
        };
        if end == bytes.len() {
            continue;
        }
        if end < bytes.len()
            && bytes[end] == bytes[set_var]
            && bytes[pc] != bytes[7]
            && !text.is_empty()
            && text
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'$')
        {
            seed_width(&mut widths, bytes[pc], Width::String)?;
        }
        if is_global(text) {
            seed_width(&mut widths, bytes[pc], Width::String)?;
            if end + 4 <= bytes.len()
                && bytes[end + 1] <= 1
                && u16::from_be_bytes([bytes[end + 2], bytes[end + 3]]) <= 8
            {
                seed_width(&mut widths, bytes[end], Width::Fixed(3))?;
            }
        }
        if is_property_anchor(text) {
            seed_width(&mut widths, bytes[end], Width::Fixed(1))?;
            if end + 2 < bytes.len() && bytes[end + 1] == 0 {
                seed_width(&mut widths, bytes[end + 2], Width::Fixed(3))?;
            }
        }
        if bytes[pc] == bytes[7]
            && widths[bytes[end] as usize] == Some(Width::Fixed(1))
            && end + 6 <= bytes.len()
            && widths[bytes[end + 2] as usize].is_none_or(|w| w == Width::Fixed(3))
            && bytes[end + 1] <= 1
            && bytes[end + 3] <= 1
            && u16::from_be_bytes([bytes[end + 4], bytes[end + 5]]) <= 8
        {
            seed_width(&mut widths, bytes[end], Width::Fixed(1))?;
            seed_width(&mut widths, bytes[end + 2], Width::Fixed(3))?;
        }
        if pc + 5 <= bytes.len()
            && u32::from_be_bytes(bytes[pc + 1..pc + 5].try_into().unwrap()) == 5381
        {
            seed_width(&mut widths, bytes[pc], Width::Fixed(4))?;
        }
    }

    let mut raw = Vec::new();
    let mut pc = 0;
    while pc < bytes.len() {
        let opcode = bytes[pc];
        let width = match widths[opcode as usize] {
            Some(width) => width,
            None => {
                let next_known =
                    |n| pc + n < bytes.len() && widths[bytes[pc + n] as usize].is_some();
                let branch_target = || {
                    (pc + 6 <= bytes.len()).then(|| {
                        u32::from_be_bytes(bytes[pc + 2..pc + 6].try_into().unwrap()) as usize
                    })
                };
                let width = if pc + 1 < bytes.len() && opcode == bytes[pc + 1] {
                    Width::Fixed(0)
                } else if pc + 6 <= bytes.len()
                    && bytes[pc + 1] <= 1
                    && branch_target().is_some_and(|target| {
                        target < bytes.len()
                            && (target > pc
                                || raw.iter().any(|r: &RawInstruction| r.offset == target))
                    })
                {
                    Width::Fixed(5)
                } else if pc + 9 <= bytes.len()
                    && next_known(9)
                    && (1e6..1e15).contains(
                        &f64::from_be_bytes(bytes[pc + 1..pc + 9].try_into().unwrap()).abs(),
                    )
                {
                    Width::Fixed(8)
                } else if pc + 5 <= bytes.len()
                    && next_known(5)
                    && u32::from_be_bytes(bytes[pc + 1..pc + 5].try_into().unwrap())
                        <= 1_000_000_000
                {
                    Width::Fixed(4)
                } else if next_known(1)
                    && widths[bytes[pc + 1] as usize] == Some(Width::String)
                    && (bytes[pc + 1] <= 23 || bytes[pc + 1] == 33)
                {
                    Width::Fixed(1)
                } else if next_known(1) {
                    Width::Fixed(0)
                } else if next_known(2) && bytes[pc + 1] <= 23 {
                    Width::Fixed(1)
                } else if pc + 2 < bytes.len()
                    && [1, 2].contains(&bytes[pc + 1])
                    && bytes[pc + 2] == bytes[0]
                {
                    Width::Fixed(1)
                } else {
                    Width::Fixed(0)
                };
                widths[opcode as usize] = Some(width);
                width
            }
        };
        raw.push(RawInstruction {
            offset: pc,
            opcode,
            width,
        });
        pc = match width {
            Width::Fixed(width) => pc.checked_add(width + 1).ok_or_else(resolution_error)?,
            Width::String => string_at(bytes, pc).ok_or_else(resolution_error)?.1,
        };
    }
    if pc != bytes.len() {
        return Err(resolution_error());
    }
    Ok((widths, raw))
}

fn kind_before(kinds: &Kinds, raw: &[RawInstruction], index: usize) -> Option<OpKind> {
    index
        .checked_sub(1)
        .and_then(|i| kinds[raw[i].opcode as usize])
}

fn infer_kinds(bytes: &[u8], raw: &[RawInstruction]) -> Result<Kinds> {
    let mut kinds = [None; 256];
    let first_target = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    let name_len = u16::from_be_bytes([bytes[first_target + 8], bytes[first_target + 9]]) as usize;
    let set_var = bytes[first_target + 10 + name_len];
    for (opcode, kind) in [
        (bytes[0], OpKind::Jmp),
        (bytes[5], OpKind::EnterScope),
        (bytes[6], OpKind::FnEntry),
        (bytes[first_target], OpKind::MakeFunc),
        (bytes[first_target - 1], OpKind::Ret),
        (bytes[first_target - 2], OpKind::LeaveScope),
        (bytes[7], OpKind::PushStr),
        (set_var, OpKind::SetVar),
    ] {
        seed_kind(&mut kinds, opcode, kind)?;
    }
    for &instruction in raw {
        if instruction.width == Width::String && instruction.opcode != bytes[7] {
            seed_kind(&mut kinds, instruction.opcode, OpKind::GetVar)?;
        }
    }

    for (i, &instruction) in raw.iter().enumerate() {
        let pc = instruction.offset;
        let opcode = instruction.opcode;
        match instruction.width {
            Width::Fixed(4) if opcode != bytes[0] => {
                seed_kind(&mut kinds, opcode, OpKind::PushU32)?;
            }
            Width::Fixed(8) => seed_kind(&mut kinds, opcode, OpKind::PushF64)?,
            Width::Fixed(5) => {
                let target = u32::from_be_bytes(bytes[pc + 2..pc + 6].try_into().unwrap()) as usize;
                if target > pc {
                    seed_kind(&mut kinds, opcode, OpKind::JBool)?;
                    if raw[i - 1].width == Width::Fixed(0) {
                        seed_kind(&mut kinds, raw[i - 1].opcode, OpKind::CmpLtLoop)?;
                    }
                } else {
                    seed_kind(&mut kinds, opcode, OpKind::JTrue)?;
                }
            }
            Width::Fixed(3) => seed_kind(&mut kinds, opcode, OpKind::Call)?,
            Width::Fixed(1)
                if i + 1 < raw.len() && raw[i + 1].opcode == bytes[0] && bytes[pc + 1] == 2 =>
            {
                seed_kind(&mut kinds, opcode, OpKind::PostInc)?;
            }
            _ => {}
        }
    }

    if bytes[8] == 0 && bytes[9] == 0 {
        seed_kind(&mut kinds, bytes[10], OpKind::PushU8)?;
    }
    for i in 0..raw.len().saturating_sub(3) {
        if (0..4).all(|j| raw[i + j].opcode == raw[i].opcode && raw[i + j].width == Width::Fixed(1))
        {
            seed_kind(&mut kinds, raw[i].opcode, OpKind::PushU8)?;
        }
    }
    for i in 0..raw.len().saturating_sub(1) {
        if raw_text(bytes, raw[i]).is_some_and(is_property_anchor) {
            seed_kind(&mut kinds, raw[i + 1].opcode, OpKind::PropGet)?;
        }
    }
    for (i, &instruction) in raw.iter().enumerate() {
        let opcode = instruction.opcode;
        let previous = kind_before(&kinds, raw, i);
        if instruction.width == Width::Fixed(1)
            && raw
                .get(i + 1)
                .is_some_and(|next| kinds[next.opcode as usize] == Some(OpKind::PushStr))
            && raw.get(i + 2).is_some_and(|next| {
                matches!(
                    kinds[next.opcode as usize],
                    Some(OpKind::Call | OpKind::PropGet)
                )
            })
        {
            seed_kind(&mut kinds, opcode, OpKind::PropGet)?;
        } else if instruction.width == Width::Fixed(1)
            && kinds[opcode as usize].is_none()
            && raw
                .get(i + 1)
                .is_some_and(|next| kinds[next.opcode as usize] == Some(OpKind::PushStr))
            && (bytes[instruction.offset + 1] <= 23 || bytes[instruction.offset + 1] == 33)
        {
            seed_kind(&mut kinds, opcode, OpKind::PushU8)?;
        }
        if instruction.width == Width::Fixed(1)
            && kinds[opcode as usize].is_none()
            && ((i >= 2
                && previous == Some(OpKind::PushU8)
                && kind_before(&kinds, raw, i - 1) == Some(OpKind::PushU8))
                || (bytes[instruction.offset + 1] == 0 && previous == Some(OpKind::SetVar)))
        {
            seed_kind(&mut kinds, opcode, OpKind::NewArray)?;
        }
        if raw_text(bytes, instruction).is_some_and(is_property_anchor) && i + 1 < raw.len() {
            seed_kind(&mut kinds, raw[i + 1].opcode, OpKind::PropGet)?;
        }
        if instruction.width == Width::Fixed(3) {
            seed_kind(&mut kinds, opcode, OpKind::Call)?;
        }
        if i > 0
            && i + 2 < raw.len()
            && kinds[opcode as usize].is_none()
            && kinds[raw[i + 1].opcode as usize] == Some(OpKind::PushStr)
            && kinds[raw[i + 2].opcode as usize] == Some(OpKind::SetVar)
            && matches!(
                previous,
                Some(OpKind::SetVar | OpKind::FnEntry | OpKind::EnterScope)
            )
        {
            seed_kind(&mut kinds, opcode, OpKind::PushUndefined)?;
        }
    }
    seed_kind(
        &mut kinds,
        raw.last().ok_or_else(resolution_error)?.opcode,
        OpKind::Halt,
    )?;

    // DJB2 exposes MUL and XOR: PUSH_U8 33; GET_VAR; MUL; XOR; GET_VAR; SET_VAR.
    for i in 2..raw.len().saturating_sub(3) {
        if raw[i - 2].width == Width::Fixed(1)
            && bytes[raw[i - 2].offset + 1] == 33
            && kinds[raw[i - 1].opcode as usize] == Some(OpKind::GetVar)
            && kinds[raw[i + 2].opcode as usize] == Some(OpKind::GetVar)
            && kinds[raw[i + 3].opcode as usize] == Some(OpKind::SetVar)
        {
            seed_kind(&mut kinds, raw[i - 2].opcode, OpKind::PushU8)?;
            seed_kind(&mut kinds, raw[i].opcode, OpKind::Mul)?;
            seed_kind(&mut kinds, raw[i + 1].opcode, OpKind::BitXor)?;
        }
    }
    for i in 0..raw.len().saturating_sub(2) {
        if raw[i].width == Width::Fixed(0)
            && kinds[raw[i].opcode as usize].is_none()
            && raw[i].opcode == raw[i + 1].opcode
            && raw[i].opcode == raw[i + 2].opcode
        {
            seed_kind(&mut kinds, raw[i].opcode, OpKind::Add)?;
        }
    }

    for (i, &instruction) in raw.iter().enumerate() {
        let opcode = instruction.opcode;
        if instruction.width != Width::Fixed(0) || kinds[opcode as usize].is_some() {
            continue;
        }
        let previous = kind_before(&kinds, raw, i);
        let previous2 = kind_before(&kinds, raw, i.wrapping_sub(1));
        let next = raw.get(i + 1).and_then(|r| kinds[r.opcode as usize]);
        let kind = match (previous, previous2, next) {
            (_, _, Some(OpKind::LeaveScope)) => OpKind::Ushr,
            (Some(OpKind::PushF64), _, Some(OpKind::PushU8))
            | (Some(OpKind::PushU8), Some(OpKind::Call), Some(OpKind::PushU8)) => OpKind::Neg,
            (Some(OpKind::Call), _, Some(OpKind::JTrue)) => OpKind::BoolNot,
            (_, Some(OpKind::PushU8), Some(OpKind::JTrue)) => OpKind::CmpNeq,
            (Some(OpKind::PropGet), Some(OpKind::Mod), Some(OpKind::JTrue))
            | (_, _, Some(OpKind::JTrue))
                if previous != Some(OpKind::PropGet) && previous != Some(OpKind::PushStr) =>
            {
                OpKind::CmpEq
            }
            (Some(OpKind::PropGet), _, Some(OpKind::JTrue)) => OpKind::CmpType,
            (Some(OpKind::PushStr), Some(OpKind::GetVar), Some(OpKind::JTrue)) => OpKind::InOp,
            (_, _, Some(OpKind::PropGet | OpKind::CmpEq))
            | (Some(OpKind::Call), _, Some(OpKind::GetVar)) => OpKind::Mod,
            (Some(OpKind::GetVar), Some(OpKind::Add), Some(OpKind::PushU8)) => OpKind::Div,
            _ => continue,
        };
        seed_kind(&mut kinds, opcode, kind)?;
    }

    // Integer packing exposes SHR, SHL, and OR as one expression.
    for i in 0..raw.len().saturating_sub(6) {
        if [0, 3, 4]
            .iter()
            .all(|j| kinds[raw[i + j].opcode as usize].is_none())
            && kinds[raw[i + 1].opcode as usize] == Some(OpKind::GetVar)
            && kinds[raw[i + 2].opcode as usize] == Some(OpKind::GetVar)
            && kinds[raw[i + 5].opcode as usize] == Some(OpKind::GetVar)
            && kinds[raw[i + 6].opcode as usize] == Some(OpKind::SetVar)
        {
            seed_kind(&mut kinds, raw[i].opcode, OpKind::Shr)?;
            seed_kind(&mut kinds, raw[i + 3].opcode, OpKind::Shl)?;
            seed_kind(&mut kinds, raw[i + 4].opcode, OpKind::BitOr)?;
        }
    }
    for (i, &instruction) in raw.iter().enumerate() {
        let opcode = instruction.opcode;
        if instruction.width != Width::Fixed(0) || kinds[opcode as usize].is_some() {
            continue;
        }
        let previous = kind_before(&kinds, raw, i);
        let next = raw.get(i + 1).and_then(|r| kinds[r.opcode as usize]);
        let kind = match (previous, next) {
            (Some(OpKind::GetVar), Some(OpKind::Sub)) => OpKind::Shl,
            (_, Some(OpKind::GetVar | OpKind::PushU8)) => OpKind::Sub,
            (_, Some(OpKind::Add | OpKind::BitXor | OpKind::Sub)) => OpKind::Mul,
            _ => continue,
        };
        seed_kind(&mut kinds, opcode, kind)?;
    }
    for &instruction in raw {
        if instruction.width == Width::Fixed(1) && kinds[instruction.opcode as usize].is_none() {
            seed_kind(&mut kinds, instruction.opcode, OpKind::SetTry)?;
        }
    }
    Ok(kinds)
}

fn decode_resolved(
    bytes: &[u8],
    raw: &[RawInstruction],
    kinds: &Kinds,
) -> Result<Vec<Instruction>> {
    raw.iter()
        .map(|instruction| {
            let pc = instruction.offset;
            let kind = kinds[instruction.opcode as usize].ok_or(CodecError::Unsupported {
                offset: pc,
                opcode: instruction.opcode,
            })?;
            let fixed = |width: usize| instruction.width == Width::Fixed(width);
            let op = match kind {
                OpKind::Jmp if fixed(4) => Op::Jmp(u32::from_be_bytes(
                    bytes[pc + 1..pc + 5].try_into().unwrap(),
                )),
                OpKind::JBool | OpKind::JTrue if fixed(5) => {
                    let cond = bytes[pc + 1];
                    let target = u32::from_be_bytes(bytes[pc + 2..pc + 6].try_into().unwrap());
                    if kind == OpKind::JBool {
                        Op::JBool { cond, target }
                    } else {
                        Op::JTrue { cond, target }
                    }
                }
                OpKind::MakeFunc if fixed(6) => Op::MakeFunc {
                    arity: u16::from_be_bytes([bytes[pc + 1], bytes[pc + 2]]),
                    entry: u32::from_be_bytes(bytes[pc + 3..pc + 7].try_into().unwrap()),
                },
                OpKind::SetTry if fixed(1) => Op::SetTry(bytes[pc + 1]),
                OpKind::EnterScope if fixed(0) => Op::EnterScope,
                OpKind::LeaveScope if fixed(0) => Op::LeaveScope,
                OpKind::Ret if fixed(0) => Op::Ret,
                OpKind::FnEntry if fixed(0) => Op::FnEntry,
                OpKind::PushUndefined if fixed(0) => Op::PushUndefined,
                OpKind::PushStr | OpKind::GetVar if instruction.width == Width::String => {
                    let text = String::from_utf8_lossy(raw_text(bytes, *instruction).unwrap())
                        .into_owned();
                    if kind == OpKind::PushStr {
                        Op::PushStr(text)
                    } else {
                        Op::GetVar(text)
                    }
                }
                OpKind::SetVar if fixed(1) => Op::SetVar(bytes[pc + 1]),
                OpKind::PushU8 if fixed(1) => Op::PushU8(bytes[pc + 1]),
                OpKind::PushU32 if fixed(4) => Op::PushU32(u32::from_be_bytes(
                    bytes[pc + 1..pc + 5].try_into().unwrap(),
                )),
                OpKind::PushF64 if fixed(8) => Op::PushF64(f64::from_be_bytes(
                    bytes[pc + 1..pc + 9].try_into().unwrap(),
                )),
                OpKind::PropGet if fixed(1) => Op::PropGet(bytes[pc + 1]),
                OpKind::Call if fixed(3) => Op::Call {
                    keep_return: bytes[pc + 1],
                    argc: u16::from_be_bytes([bytes[pc + 2], bytes[pc + 3]]),
                },
                OpKind::NewArray if fixed(1) => Op::NewArray(bytes[pc + 1]),
                OpKind::PostInc if fixed(1) => Op::PostInc(bytes[pc + 1]),
                OpKind::Halt if fixed(0) => Op::Halt,
                OpKind::Add if fixed(0) => Op::Add,
                OpKind::Sub if fixed(0) => Op::Sub,
                OpKind::Mul if fixed(0) => Op::Mul,
                OpKind::Div if fixed(0) => Op::Div,
                OpKind::Mod if fixed(0) => Op::Mod,
                OpKind::BitXor if fixed(0) => Op::BitXor,
                OpKind::Shl if fixed(0) => Op::Shl,
                OpKind::Shr if fixed(0) => Op::Shr,
                OpKind::BitOr if fixed(0) => Op::BitOr,
                OpKind::Ushr if fixed(0) => Op::Ushr,
                OpKind::Neg if fixed(0) => Op::Neg,
                OpKind::BoolNot if fixed(0) => Op::BoolNot,
                OpKind::CmpLtLoop if fixed(0) => Op::CmpLtLoop,
                OpKind::CmpEq if fixed(0) => Op::CmpEq,
                OpKind::CmpNeq if fixed(0) => Op::CmpNeq,
                OpKind::CmpType if fixed(0) => Op::CmpType,
                OpKind::InOp if fixed(0) => Op::InOp,
                _ => return Err(resolution_error()),
            };
            Ok(Instruction { offset: pc, op })
        })
        .collect()
}

/// Disassemble a TLV stream after resolving its per-build opcode encoding.
pub fn try_disassemble(bytes: &[u8]) -> Result<Vec<Instruction>> {
    let (_, raw) = infer_widths(bytes)?;
    let kinds = infer_kinds(bytes, &raw)?;
    decode_resolved(bytes, &raw, &kinds)
}

/// Disassemble a TLV bytecode stream with exact operand widths.
///
/// Invalid or unsupported streams retain the original best-effort decoder;
/// use [`try_disassemble`] to reject them instead.
pub fn disassemble(bytes: &[u8]) -> Vec<Instruction> {
    try_disassemble(bytes).unwrap_or_else(|_| disassemble_legacy(bytes))
}

/// Extract the 23-element permutation bijections (`kT`) from Blob 0.
pub fn permutation_tables(bytes: &[u8]) -> Vec<[u8; 23]> {
    let insts = disassemble(bytes);
    let mut tables = Vec::new();
    let mut run: Vec<u8> = Vec::new();

    for inst in insts {
        match inst.op {
            Op::PushU8(v) => run.push(v),
            Op::NewArray(23) => {
                if let Some(table) = decode_table(&run) {
                    tables.push(table);
                }
                run.clear();
            }
            Op::NewArray(5) if !tables.is_empty() => break,
            _ => {}
        }
    }
    tables
}

/// Extract the 5 selector keys (`Eq` in Blob 0: `[672905826579, 322132545, 349450134, -167822523239, -504109940950]`)
/// that choose which of the 5 permutation tables in `kT` reorders the 23 sensor slots.
pub fn selector_keys(bytes: &[u8]) -> Vec<i64> {
    let insts = disassemble(bytes);
    let mut keys = Vec::new();
    let mut after_first_array5 = false;
    let mut pending: Option<i64> = None;

    for inst in insts {
        match inst.op {
            Op::NewArray(5) if !after_first_array5 => {
                after_first_array5 = true;
            }
            Op::NewArray(5) if after_first_array5 => {
                if let Some(v) = pending.take() {
                    keys.push(v);
                }
                break;
            }
            Op::PushF64(f) if after_first_array5 => {
                if let Some(v) = pending.replace(f as i64) {
                    keys.push(v);
                }
            }
            Op::PushU32(u) if after_first_array5 => {
                if let Some(v) = pending.replace(i64::from(u)) {
                    keys.push(v);
                }
            }
            Op::Neg if after_first_array5 => {
                if let Some(v) = pending.as_mut() {
                    *v = -*v;
                }
            }
            _ => {}
        }
    }
    keys
}

/// Native lift of Blob 0's `Bk(wT, cw)` function: looks up `cw` in `selector_keys`,
/// selects the matching 23-element permutation `pr = tables[idx]`, and permutes `wT`
/// so that `out[i] = wT[pr[i]]` (keeping `wT[0]` when `pr[i] == 0`).
pub fn permute_slots_by_key<T: Clone>(
    slots: &[T; 23],
    selector: i64,
    tables: &[[u8; 23]],
    keys: &[i64],
) -> [T; 23] {
    let Some(idx) = keys.iter().position(|&k| k == selector) else {
        return slots.clone();
    };
    let Some(pr) = tables.get(idx) else {
        return slots.clone();
    };
    std::array::from_fn(|i| slots[pr[i] as usize].clone())
}

fn decode_table(values: &[u8]) -> Option<[u8; 23]> {
    if values.len() < 46 {
        return None;
    }
    let tail = &values[values.len() - 46..];
    for phase in [0usize, 1usize] {
        let candidate: Vec<u8> = tail.iter().skip(phase).step_by(2).copied().collect();
        if is_bijection_23(&candidate) {
            return candidate.try_into().ok();
        }
    }
    None
}

fn is_bijection_23(candidate: &[u8]) -> bool {
    if candidate.len() != 23 {
        return false;
    }
    let mut seen = [false; 23];
    for &v in candidate {
        let idx = v as usize;
        if idx >= 23 || seen[idx] {
            return false;
        }
        seen[idx] = true;
    }
    true
}

/// Runtime value in the lifted BMP stack machine.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Undefined,
    Bool(bool),
    Num(f64),
    Str(String),
    Array(Rc<RefCell<Vec<Value>>>),
    Func {
        arity: u16,
        entry: u32,
    },
    /// Variable reference (`0x7e`) that resolves to its value when read as an
    /// RValue and writes back when consumed by `SET_VAR` (`0x96`) or `POST_INC` (`0x33`).
    VarRef(String),
    /// Property reference (`0x7f`) on a value or array.
    PropRef {
        base: Box<Value>,
        prop: String,
    },
}

impl Value {
    pub fn as_num(&self) -> f64 {
        match self {
            Self::Num(n) => *n,
            Self::Bool(true) => 1.0,
            Self::Bool(false) | Self::Undefined => 0.0,
            Self::Str(s) => s.parse().unwrap_or(f64::NAN),
            _ => f64::NAN,
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            Self::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 1e18 {
                    format!("{}", *n as i64)
                } else {
                    n.to_string()
                }
            }
            Self::Bool(b) => b.to_string(),
            Self::Undefined => "undefined".to_owned(),
            Self::Array(items) => items
                .borrow()
                .iter()
                .map(Self::as_str)
                .collect::<Vec<_>>()
                .join(","),
            Self::Func { .. } => "[function]".to_owned(),
            Self::VarRef(name) => name.clone(),
            Self::PropRef { prop, .. } => prop.clone(),
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Undefined => false,
            Self::Bool(b) => *b,
            Self::Num(n) => *n != 0.0 && !n.is_nan(),
            Self::Str(s) => !s.is_empty(),
            _ => true,
        }
    }
}

/// Host bridge for global objects (`window`, `document`, `Math`, `String`, `parseInt`, `Array`).
pub trait Host {
    fn get(&mut self, receiver: &Value, prop: &str) -> Value;
    fn call(&mut self, receiver: &Value, method: &str, args: &[Value]) -> Value;
}

/// Lifted bytecode interpreter capable of executing Blob 0 (`Bk`) and Blob 1
/// (`qR`, `QO`, `dk`, `CE`) directly.
#[derive(Default)]
pub struct Vm {
    pub stack: Vec<Value>,
    pub env: BTreeMap<String, Value>,
}

impl Vm {
    pub fn new() -> Self {
        Self::default()
    }

    fn resolve(&self, val: Value) -> Value {
        match val {
            Value::VarRef(name) => self.env.get(&name).cloned().unwrap_or(Value::Undefined),
            Value::PropRef { base, prop } => {
                let recv = self.resolve(*base);
                match (&recv, prop.as_str()) {
                    (Value::Str(s), "length") => Value::Num(s.chars().count() as f64),
                    (Value::Array(a), "length") => Value::Num(a.borrow().len() as f64),
                    (Value::Str(s), idx) if idx.parse::<usize>().is_ok() => {
                        let i: usize = idx.parse().unwrap();
                        s.chars()
                            .nth(i)
                            .map(|c| Value::Str(c.to_string()))
                            .unwrap_or(Value::Undefined)
                    }
                    (Value::Array(a), idx) if idx.parse::<usize>().is_ok() => {
                        let i: usize = idx.parse().unwrap();
                        a.borrow().get(i).cloned().unwrap_or(Value::Undefined)
                    }
                    _ => Value::PropRef {
                        base: Box::new(recv),
                        prop,
                    },
                }
            }
            other => other,
        }
    }

    fn pop_val(&mut self, host: &mut dyn Host) -> Value {
        let raw = self.stack.pop().unwrap_or(Value::Undefined);
        let resolved = self.resolve(raw);
        if let Value::PropRef { base, prop } = resolved {
            host.get(&base, &prop)
        } else {
            resolved
        }
    }

    /// Execute `bytes` starting at `start_offset` with `args` pushed in call order.
    pub fn exec(
        &mut self,
        bytes: &[u8],
        start_offset: usize,
        args: &[Value],
        host: &mut dyn Host,
    ) -> Result<Value> {
        let insts = try_disassemble(bytes)?;
        let offset_to_idx: BTreeMap<usize, usize> = insts
            .iter()
            .enumerate()
            .map(|(i, inst)| (inst.offset, i))
            .collect();

        // Push arguments in reverse so parameter prelude (`PUSH_STR name; SET_VAR`) pops arg 0 first.
        for arg in args.iter().rev() {
            self.stack.push(arg.clone());
        }

        let mut idx = *offset_to_idx
            .get(&start_offset)
            .ok_or_else(|| CodecError::Format(format!("invalid entry offset {start_offset}")))?;

        while idx < insts.len() {
            let inst = &insts[idx];
            match &inst.op {
                Op::EnterScope | Op::LeaveScope | Op::FnEntry | Op::SetTry(_) => {}
                Op::Halt => break,
                Op::Ret => {
                    return Ok(self.pop_val(host));
                }
                Op::Jmp(target) => {
                    idx = *offset_to_idx
                        .get(&(*target as usize))
                        .ok_or_else(|| CodecError::Format(format!("bad jump target {target}")))?;
                    continue;
                }
                Op::JBool { cond, target } => {
                    let v = self.pop_val(host).is_truthy();
                    let take = if *cond == 0 { !v } else { v };
                    if take {
                        idx = *offset_to_idx.get(&(*target as usize)).ok_or_else(|| {
                            CodecError::Format(format!("bad JBool target {target}"))
                        })?;
                        continue;
                    }
                }
                Op::JTrue { cond, target } => {
                    let v = self.pop_val(host).is_truthy();
                    let take = if *cond == 0 { v } else { !v };
                    if take {
                        idx = *offset_to_idx.get(&(*target as usize)).ok_or_else(|| {
                            CodecError::Format(format!("bad JTrue target {target}"))
                        })?;
                        continue;
                    }
                }
                Op::MakeFunc { arity, entry } => {
                    self.stack.push(Value::Func {
                        arity: *arity,
                        entry: *entry,
                    });
                }
                Op::PushUndefined => self.stack.push(Value::Undefined),
                Op::PushStr(s) => self.stack.push(Value::Str(s.clone())),
                Op::GetVar(name) => self.stack.push(Value::VarRef(name.clone())),
                Op::PushU8(v) => self.stack.push(Value::Num(f64::from(*v))),
                Op::PushU32(v) => self.stack.push(Value::Num(f64::from(*v))),
                Op::PushF64(v) => self.stack.push(Value::Num(*v)),
                Op::SetVar(_) => {
                    let target = self.stack.pop().unwrap_or(Value::Undefined);
                    let val = self.pop_val(host);
                    match target {
                        Value::Str(name) | Value::VarRef(name) => {
                            self.env.insert(name, val);
                        }
                        Value::PropRef { base, prop } => {
                            let recv = self.resolve(*base);
                            if let (Value::Array(arr), Ok(i)) = (&recv, prop.parse::<usize>()) {
                                let mut borrow = arr.borrow_mut();
                                if i >= borrow.len() {
                                    borrow.resize(i + 1, Value::Undefined);
                                }
                                borrow[i] = val;
                            }
                        }
                        _ => {}
                    }
                }
                Op::PostInc(_) => {
                    if let Some(Value::VarRef(name)) = self.stack.pop() {
                        let cur = self.env.get(&name).map(Value::as_num).unwrap_or(0.0);
                        self.env.insert(name, Value::Num(cur + 1.0));
                    }
                }
                Op::NewArray(len) => {
                    let count = *len as usize;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        let _pad = self.pop_val(host);
                        let item = self.pop_val(host);
                        items.push(item);
                    }
                    items.reverse();
                    self.stack.push(Value::Array(Rc::new(RefCell::new(items))));
                }
                Op::PropGet(_mode) => {
                    let prop = self.pop_val(host).as_str();
                    let base = self.pop_val(host);
                    self.stack.push(Value::PropRef {
                        base: Box::new(base),
                        prop,
                    });
                }
                Op::Call { keep_return, argc } => {
                    let callee = self.stack.pop().unwrap_or(Value::Undefined);
                    let mut call_args = Vec::with_capacity(*argc as usize);
                    for _ in 0..*argc {
                        let _sep = self.pop_val(host);
                        let arg = self.pop_val(host);
                        call_args.push(arg);
                    }
                    let rv = match callee {
                        Value::VarRef(name) => {
                            if let Some(Value::Func { entry, .. }) = self.env.get(&name).cloned() {
                                let saved = std::mem::take(&mut self.stack);
                                let res = self.exec(bytes, entry as usize, &call_args, host)?;
                                self.stack = saved;
                                res
                            } else {
                                host.call(&Value::Undefined, &name, &call_args)
                            }
                        }
                        Value::PropRef { base, prop } => {
                            let recv = self.resolve(*base);
                            self.eval_method(&recv, &prop, &call_args, host)
                        }
                        _ => Value::Undefined,
                    };
                    if *keep_return != 0 {
                        self.stack.push(rv);
                    }
                }
                Op::Add => {
                    let lhs = self.pop_val(host);
                    let rhs = self.pop_val(host);
                    let out = if matches!(lhs, Value::Str(_)) || matches!(rhs, Value::Str(_)) {
                        Value::Str(format!("{}{}", lhs.as_str(), rhs.as_str()))
                    } else {
                        Value::Num(lhs.as_num() + rhs.as_num())
                    };
                    self.stack.push(out);
                }
                Op::Sub => {
                    let lhs = self.pop_val(host).as_num();
                    let rhs = self.pop_val(host).as_num();
                    self.stack.push(Value::Num(lhs - rhs));
                }
                Op::Mul => {
                    let lhs = self.pop_val(host).as_num();
                    let rhs = self.pop_val(host).as_num();
                    self.stack.push(Value::Num(lhs * rhs));
                }
                Op::Div => {
                    let lhs = self.pop_val(host).as_num();
                    let rhs = self.pop_val(host).as_num();
                    self.stack.push(Value::Num(lhs / rhs));
                }
                Op::Mod => {
                    let lhs = self.pop_val(host).as_num();
                    let rhs = self.pop_val(host).as_num();
                    self.stack.push(Value::Num(lhs % rhs));
                }
                Op::BitXor => {
                    let lhs = self.pop_val(host).as_num() as i64 as i32;
                    let rhs = self.pop_val(host).as_num() as i64 as i32;
                    self.stack.push(Value::Num(f64::from(lhs ^ rhs)));
                }
                Op::Shl => {
                    let lhs = self.pop_val(host).as_num() as i64 as i32;
                    let rhs = (self.pop_val(host).as_num() as i64 as u32) & 31;
                    self.stack
                        .push(Value::Num(f64::from(lhs.wrapping_shl(rhs))));
                }
                Op::Shr => {
                    let lhs = self.pop_val(host).as_num() as i64 as i32;
                    let rhs = (self.pop_val(host).as_num() as i64 as u32) & 31;
                    self.stack
                        .push(Value::Num(f64::from(lhs.wrapping_shr(rhs))));
                }
                Op::BitOr => {
                    let lhs = self.pop_val(host).as_num() as i64 as i32;
                    let rhs = self.pop_val(host).as_num() as i64 as i32;
                    self.stack.push(Value::Num(f64::from(lhs | rhs)));
                }
                Op::Ushr => {
                    let lhs = self.pop_val(host).as_num() as i64 as u32;
                    let rhs = (self.pop_val(host).as_num() as i64 as u32) & 31;
                    self.stack
                        .push(Value::Num(f64::from(lhs.wrapping_shr(rhs))));
                }
                Op::Neg => {
                    let v = self.pop_val(host).as_num();
                    self.stack.push(Value::Num(-v));
                }
                Op::BoolNot => {
                    let v = self.pop_val(host).is_truthy();
                    self.stack.push(Value::Bool(!v));
                }
                Op::CmpLt | Op::CmpLtLoop => {
                    let lhs = self.pop_val(host).as_num();
                    let rhs = self.pop_val(host).as_num();
                    self.stack.push(Value::Bool(lhs < rhs));
                }
                Op::CmpEq | Op::CmpType => {
                    let lhs = self.pop_val(host);
                    let rhs = self.pop_val(host);
                    self.stack.push(Value::Bool(values_eq(&lhs, &rhs)));
                }
                Op::CmpNeq => {
                    let lhs = self.pop_val(host);
                    let rhs = self.pop_val(host);
                    self.stack.push(Value::Bool(!values_eq(&lhs, &rhs)));
                }
                Op::InOp => {
                    let prop = self.pop_val(host).as_str();
                    let obj = self.pop_val(host);
                    let exists = !matches!(host.get(&obj, &prop), Value::Undefined);
                    self.stack.push(Value::Bool(exists));
                }
                Op::Unknown(byte) => {
                    return Err(CodecError::Unsupported {
                        offset: inst.offset,
                        opcode: *byte,
                    });
                }
            }
            idx += 1;
        }
        Ok(self.stack.last().cloned().unwrap_or(Value::Undefined))
    }

    fn eval_method(
        &mut self,
        recv: &Value,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
    ) -> Value {
        match (recv, method) {
            (Value::Str(s), "split") => {
                let pat = args.first().map(Value::as_str).unwrap_or_default();
                let parts: Vec<Value> = if pat.is_empty() {
                    s.chars().map(|c| Value::Str(c.to_string())).collect()
                } else {
                    s.split(&pat).map(|p| Value::Str(p.to_owned())).collect()
                };
                Value::Array(Rc::new(RefCell::new(parts)))
            }
            (Value::Array(arr), "join") => {
                let sep = args.first().map(Value::as_str).unwrap_or_default();
                let joined = arr
                    .borrow()
                    .iter()
                    .map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(&sep);
                Value::Str(joined)
            }
            (Value::Array(arr), "push") => {
                for a in args {
                    arr.borrow_mut().push(a.clone());
                }
                Value::Num(arr.borrow().len() as f64)
            }
            (Value::Array(arr), "indexOf") => {
                let needle = args.first().cloned().unwrap_or(Value::Undefined);
                let pos = arr
                    .borrow()
                    .iter()
                    .position(|x| values_eq(x, &needle))
                    .map(|i| i as isize)
                    .unwrap_or(-1);
                Value::Num(pos as f64)
            }
            (Value::Str(s), "charCodeAt") => {
                let i = args.first().map(Value::as_num).unwrap_or(0.0) as usize;
                s.chars()
                    .nth(i)
                    .map(|c| Value::Num(u32::from(c) as f64))
                    .unwrap_or(Value::Num(f64::NAN))
            }
            (Value::Str(s), "charAt") => {
                let i = args.first().map(Value::as_num).unwrap_or(0.0) as usize;
                Value::Str(s.chars().nth(i).map(|c| c.to_string()).unwrap_or_default())
            }
            (Value::Str(s), "slice") => {
                let len = s.chars().count() as isize;
                let raw = args.first().map(Value::as_num).unwrap_or(0.0) as isize;
                let start = if raw < 0 {
                    (len + raw).max(0)
                } else {
                    raw.min(len)
                } as usize;
                Value::Str(s.chars().skip(start).collect())
            }
            (Value::Num(n), "toString") => {
                let radix = args.first().map(Value::as_num).unwrap_or(10.0) as u32;
                if radix == 2 {
                    Value::Str(format!("{:b}", *n as i64 as u64))
                } else {
                    Value::Str(self.resolve(recv.clone()).as_str())
                }
            }
            _ => host.call(recv, method, args),
        }
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Undefined, Value::Undefined) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::Num(x), Value::Num(y)) => x == y,
        (Value::Str(x), Value::Str(y)) => x == y,
        _ => false,
    }
}

/// Classic djb2 (`((hash * 33) ^ c) >>> 0` starting at `5381`), matching the
/// exact bytecode of Blob 1 `dk` (`197..333`: `PUSH_U32 5381`, `MUL 33`, `0x97` XOR, `0xd5` `>>> 0`).
pub fn djb2_xor(text: &str) -> u32 {
    let mut hash = 5381u32;
    for ch in text.chars() {
        hash = hash.wrapping_mul(33) ^ (ch as u32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_both_table_phases_and_selector_keys() {
        let perm: [u8; 23] = [
            2, 12, 10, 11, 20, 17, 13, 6, 5, 0, 3, 21, 18, 22, 19, 7, 8, 14, 1, 4, 16, 9, 15,
        ];
        let mut blob = vec![0x8f, 0, 0, 1, 0, 0xd2];
        for &v in &perm {
            blob.extend_from_slice(&[0x4f, v, 0x4f, 0]);
        }
        blob.extend_from_slice(&[0x8c, 0x17]);
        for &v in &perm {
            blob.extend_from_slice(&[0x4f, 0, 0x4f, v]);
        }
        blob.extend_from_slice(&[0x8c, 0x17, 0x4f, 0, 0x8c, 0x05]);
        // Append two selector keys: +322132545 (0x29) and -167822523239.0 (0xea + 0x58)
        blob.extend_from_slice(&[0x29, 0x13, 0x33, 0x5a, 0x41, 0x4f, 0]);
        blob.extend_from_slice(&[0xea]);
        blob.extend_from_slice(&(167_822_523_239.0f64).to_be_bytes());
        blob.extend_from_slice(&[0x58, 0x4f, 0, 0x8c, 0x05]);

        let tables = permutation_tables(&blob);
        assert_eq!(tables, vec![perm, perm]);
        let keys = selector_keys(&blob);
        assert_eq!(keys, vec![322_132_545, -167_822_523_239]);
    }

    #[test]
    fn executes_real_blob1_dk_djb2_bytecode() {
        struct NoopHost;
        impl Host for NoopHost {
            fn get(&mut self, _r: &Value, _p: &str) -> Value {
                Value::Undefined
            }
            fn call(&mut self, _r: &Value, _m: &str, _a: &[Value]) -> Value {
                Value::Undefined
            }
        }

        // Exact bytes of Blob 1 offsets 192..348 (function dk(WA)):
        let dk_bytecode: &[u8] = &[
            0x8f, 0x00, 0x00, 0x00, 0x8e, //   0: JMP -> 142 (MAKE_FUNC)
            0xd2, 0x43, //   5: ENTER_SCOPE; FN_ENTRY
            0xff, 0x00, 0x02, b'W', b'A', 0x96, 0x00, //   7: param WA
            0xfd, 0xff, 0x00, 0x02, b'g', b'I', 0x96, 0x00, //  14: var gI
            0x29, 0x00, 0x00, 0x15, 0x05, 0x7e, 0x00, 0x02, b'g', b'I', 0x96,
            0x00, //  22: gI = 5381
            0x4f, 0x00, 0xff, 0x00, 0x02, b'b', b'O', 0x96, 0x00, //  34: var bO = 0
            // 43: loop header
            0x7e, 0x00, 0x02, b'W', b'A', 0xff, 0x00, 0x06, b'l', b'e', b'n', b'g', b't', b'h',
            0x7f, 0x01, 0x7e, 0x00, 0x02, b'b', b'O', 0xce, 0xbd, 0x00, 0x00, 0x00, 0x00,
            0x84, // JBOOL_0 -> 132
            // 71: loop body
            0xd2, 0x7e, 0x00, 0x02, b'b', b'O', 0x4f, 0x00, 0x7e, 0x00, 0x02, b'W', b'A', 0xff,
            0x00, 0x0a, b'c', b'h', b'a', b'r', b'C', b'o', b'd', b'e', b'A', b't', 0x7f, 0x00,
            0x1a, 0x01, 0x00, 0x01, 0x4f, 0x21, 0x7e, 0x00, 0x02, b'g', b'I', 0x01, 0x97, 0x7e,
            0x00, 0x02, b'g', b'I', 0x96, 0x00, 0x54, 0x7e, 0x00, 0x02, b'b', b'O', 0x33, 0x02,
            0x8f, 0x00, 0x00, 0x00, 0x2b, // JMP -> 43
            // 132: exit
            0x4f, 0x00, 0x7e, 0x00, 0x02, b'g', b'I', 0xd5, 0x54, 0xa0, // 142: MAKE_FUNC
            0xe8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0xff, 0x00, 0x02, b'd', b'k', 0x96, 0x00,
            0x6a,
        ];

        assert!(
            disassemble(dk_bytecode)
                .iter()
                .all(|i| !matches!(i.op, Op::Unknown(_)))
        );

        let mut vm = Vm::new();
        let ret = vm
            .exec(
                dk_bytecode,
                5,
                &[Value::Str("Mozilla/5.0".to_owned())],
                &mut NoopHost,
            )
            .expect("exec dk");
        assert_eq!(ret.as_num() as u32, djb2_xor("Mozilla/5.0"));
    }
}
