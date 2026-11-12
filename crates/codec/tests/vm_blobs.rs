//! End-to-end verification of the full BMP VM lift against the two real
//! Akamai bytecode blobs (959-byte `kT`/`Eq` permutation blob and the
//! 2,481-byte serializer blob with `qR`, `QO`, `dk`, `CE`).

use akamai_codec::vm::{
    Host, Op, Value, Vm, disassemble, djb2_xor, permutation_tables, permute_slots_by_key,
    selector_keys,
};

const BLOB0: &[u8] = include_bytes!("fixtures/blob0.bin");
const BLOB1: &[u8] = include_bytes!("fixtures/blob1.bin");

#[test]
fn disassembles_every_byte_of_both_blobs_without_desync() {
    let b0 = disassemble(BLOB0);
    let b1 = disassemble(BLOB1);
    assert_eq!(b0.len(), 382);
    assert_eq!(b1.len(), 673);
    assert!(b0.iter().all(|i| !matches!(i.op, Op::Unknown(_))));
    assert!(b1.iter().all(|i| !matches!(i.op, Op::Unknown(_))));

    // Offsets the old 9-byte `PUSHnum` misparse used to corrupt:
    assert!(b1.iter().any(|i| matches!(i.op, Op::Jmp(122))));
    assert!(b1.iter().any(|i| matches!(
        i.op,
        Op::MakeFunc {
            arity: 1,
            entry: 197
        }
    )));
    assert!(b1.iter().any(|i| matches!(
        i.op,
        Op::MakeFunc {
            arity: 4,
            entry: 353
        }
    )));
    // Offset 2390 is `0x7e 00 06 "window"`, previously eaten by a fake PUSHnum.
    assert!(
        b1.iter()
            .any(|i| i.offset == 2390 && i.op == Op::GetVar("window".to_owned()))
    );
    // Blob 1 uses all four bitwise/arithmetic ops that were mislabeled before.
    assert!(b1.iter().any(|i| matches!(i.op, Op::Shl)));
    assert!(b1.iter().any(|i| matches!(i.op, Op::Shr)));
    assert!(b1.iter().any(|i| matches!(i.op, Op::Div)));
    assert!(b1.iter().any(|i| matches!(i.op, Op::BitXor)));
}

#[test]
fn blob0_tables_and_selector_keys_match_reference() {
    let tables = permutation_tables(BLOB0);
    assert_eq!(tables.len(), 5);
    for table in &tables {
        let mut sorted = *table;
        sorted.sort_unstable();
        assert_eq!(sorted, std::array::from_fn::<_, 23, _>(|i| i as u8));
    }
    assert_eq!(
        tables[0],
        [
            2, 12, 10, 11, 20, 17, 13, 6, 5, 0, 3, 21, 18, 22, 19, 7, 8, 14, 1, 4, 16, 9, 15
        ]
    );
    assert_eq!(
        tables[1],
        [
            13, 11, 1, 15, 20, 21, 22, 2, 3, 0, 9, 6, 16, 12, 10, 5, 18, 8, 17, 7, 4, 14, 19
        ]
    );
    assert_eq!(
        tables[2],
        [
            22, 8, 6, 16, 5, 7, 10, 3, 4, 19, 9, 14, 13, 1, 2, 11, 18, 21, 20, 17, 15, 0, 12
        ]
    );
    assert_eq!(
        tables[3],
        [
            9, 1, 6, 15, 4, 16, 7, 18, 22, 17, 20, 2, 8, 19, 5, 21, 12, 14, 10, 11, 3, 0, 13
        ]
    );
    assert_eq!(
        tables[4],
        [
            10, 11, 21, 8, 2, 5, 6, 1, 3, 4, 12, 20, 22, 16, 17, 13, 19, 18, 14, 0, 9, 7, 15
        ]
    );

    assert_eq!(
        selector_keys(BLOB0),
        vec![
            672_905_826_579,
            322_132_545,
            349_450_134,
            -167_822_523_239,
            -504_109_940_950
        ]
    );
}

/// Native `Bk(wT, cw)` helper on table 2 (`selector = 349450134`).
#[test]
fn permute_slots_matches_blob0_permutation_semantics() {
    let slots: [usize; 23] = std::array::from_fn(|i| i);
    let tables = permutation_tables(BLOB0);
    let keys = selector_keys(BLOB0);
    let out = permute_slots_by_key(&slots, 349_450_134, &tables, &keys);
    let pr = tables[2];
    for (i, val) in out.iter().enumerate() {
        assert_eq!(*val, pr[i] as usize, "slot {i}");
    }
}

struct BlobHost;

impl Host for BlobHost {
    fn get(&mut self, receiver: &Value, prop: &str) -> Value {
        match (receiver, prop) {
            (Value::Str(name), "bmak") if name == "window" => Value::Str("bmak".to_owned()),
            (Value::Str(_), "startTs") => Value::Num(1_700_000_000_000.0),
            _ => Value::Undefined,
        }
    }

    fn call(&mut self, receiver: &Value, method: &str, args: &[Value]) -> Value {
        match (receiver.as_str().as_str(), method) {
            ("Array", "isArray") => Value::Bool(matches!(args.first(), Some(Value::Array(_)))),
            ("Array", "indexOf") => Value::Num(-1.0),
            _ => Value::Undefined,
        }
    }
}

#[test]
fn executes_blob1_dk_end_to_end_on_a_real_user_agent() {
    let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    let mut vm = Vm::new();
    // Offset 197 = `dk(WA)` ENTER_SCOPE (offsets 0..192 are the qR/QO closures).
    let ret = vm
        .exec(BLOB1, 197, &[Value::Str(ua.to_owned())], &mut BlobHost)
        .expect("dk executes");
    assert_eq!(ret.as_num() as u32, djb2_xor(ua));
}

#[test]
fn executes_blob0_permutation_function_on_23_sensor_slots() {
    let slots: Vec<Value> = (0..23).map(|i| Value::Num(i as f64)).collect();
    let w_t = Value::Array(std::rc::Rc::new(std::cell::RefCell::new(slots.clone())));

    // `cw = 0` is absent from `Eq`, so Bk returns wT unchanged.
    let mut vm = Vm::new();
    let ret = vm
        .exec(BLOB0, 5, &[w_t.clone(), Value::Num(0.0)], &mut BlobHost)
        .expect("Bk fallback");
    if let Value::Array(items) = ret {
        assert_eq!(items.borrow().as_slice(), slots.as_slice());
    } else {
        panic!("expected array return");
    }

    // Selector present in `Eq`: returned array must match `permute_slots_by_key`.
    let selector = 349_450_134i64;
    let mut vm = Vm::new();
    let ret = vm
        .exec(BLOB0, 5, &[w_t, Value::Num(selector as f64)], &mut BlobHost)
        .expect("Bk permutes");
    let expected = permute_slots_by_key(
        &std::array::from_fn(|i| i),
        selector,
        &permutation_tables(BLOB0),
        &selector_keys(BLOB0),
    );
    if let Value::Array(items) = ret {
        let got: Vec<usize> = items.borrow().iter().map(|v| v.as_num() as usize).collect();
        assert_eq!(got.as_slice(), expected.as_slice());
    } else {
        panic!("expected array return");
    }
}
