use super::{extract_bmak_shuffle_key, extract_bmak_ver};

const VERSION: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const OTHER_VERSION: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

fn cipher(text: &str) -> String {
    text.bytes()
        .map(|ch| char::from(b"qAzWsXeDcRv"["0123456789.".find(char::from(ch)).unwrap()]))
        .collect()
}

fn numeric_table(values: &[&str]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|s| format!("'{}'", cipher(s)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn legacy(seed: &str) -> String {
    let mut values = vec!["0"; 23];
    values[4] = "4294967295.000000";
    values[6] = "8388607.000000";
    values[8] = "65535.000000";
    values[9] = "8888888";
    values[10] = seed;
    values[11] = "1000";
    format!("const renamed = [{}, 0];", numeric_table(&values))
}

fn current(seed: &str) -> String {
    let values = [
        "4095.000000",
        "2",
        "0",
        "34",
        "1000",
        "65535.000000",
        "65793",
        "4282663",
        "8388607.000000",
        "4294967295.000000",
        "3",
        seed,
    ];
    format!(
        "function renamed() {{ return {}; }}",
        numeric_table(&values)
    )
}

fn reordered(seed: &str, extra: &str) -> String {
    let first = [
        "4294967295.000000",
        "1000",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        seed,
        extra,
    ];
    let second = [
        "65793",
        "4282663",
        "8388607.000000",
        "65535.000000",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
    ];
    format!(
        "const init = {}; const lcg = {};",
        numeric_table(&first),
        numeric_table(&second)
    )
}

fn version_table(version: &str, key_len: usize, wrapping: bool) -> String {
    let master = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabc";
    let mut key: Vec<u8> = (0..key_len).map(|i| ((i * 7 + 13) % 128) as u8).collect();
    key[5] = 255; // JS byte characters can take multiple bytes in UTF-8 source.
    if let Some(byte) = key.get_mut(8) {
        *byte = 127;
    }
    if let Some(byte) = key.get_mut(15) {
        *byte = 0;
    }
    let offset = if wrapping { master.len() - 2 } else { 0 };
    let seed: String = key
        .iter()
        .enumerate()
        .map(|(i, &ch)| char::from(ch ^ master[(offset + i) % master.len()]))
        .collect();
    let shift = key_len - 4;
    let encoded: String = version
        .bytes()
        .enumerate()
        .map(|(i, ch)| char::from(ch ^ key[(i + shift) % key_len]))
        .collect();
    format!(
        "const renamed = {};",
        serde_json::to_string(&[encoded, seed, String::from_utf8(master.to_vec()).unwrap(),])
            .unwrap()
    )
}

#[test]
fn accepts_both_anchored_numeric_layouts_without_variable_names() {
    for seed in ["1234567", "6199253", "8543578"] {
        for source in [legacy(seed), current(seed)] {
            assert_eq!(
                extract_bmak_shuffle_key(&source),
                seed.parse().ok(),
                "{source}"
            );
            let double_quoted = source.replace('\'', "\"");
            assert_eq!(extract_bmak_shuffle_key(&double_quoted), seed.parse().ok());
        }
    }
}

#[test]
fn recovers_a_unique_seed_from_split_and_reordered_numeric_tables() {
    for seed in ["1871368", "6199253", "1234567"] {
        assert_eq!(
            extract_bmak_shuffle_key(&reordered(seed, "32")),
            seed.parse().ok()
        );
    }
    assert_eq!(
        extract_bmak_shuffle_key(&reordered("1871368", "1234567")),
        None
    );
}

#[test]
fn rejects_conflicting_supported_numeric_tables_in_either_order() {
    for (first, second) in [
        (current("1234567"), legacy("7654321")),
        (legacy("7654321"), current("1234567")),
    ] {
        assert_eq!(extract_bmak_shuffle_key(&format!("{first}{second}")), None);
    }
    let same = current("1234567");
    assert_eq!(
        extract_bmak_shuffle_key(&format!("{same}{same}")),
        Some(1_234_567)
    );
}

#[test]
fn rejects_non_integer_empty_unknown_and_overflowing_seeds() {
    for seed in ["", "1.5", "4294967296"] {
        assert_eq!(extract_bmak_shuffle_key(&current(seed)), None, "{seed:?}");
        assert_eq!(extract_bmak_shuffle_key(&legacy(seed)), None, "{seed:?}");
    }
    assert_eq!(
        extract_bmak_shuffle_key(&current("1234567").replace(&cipher("1234567"), "unknown")),
        None
    );
}

#[test]
fn rejects_inconsistent_non_bijective_or_incomplete_numeric_anchors() {
    let source = current("1234567");
    assert_eq!(
        extract_bmak_shuffle_key(&source.replace(&cipher("65793"), &cipher("65795"))),
        None
    );
    assert_eq!(extract_bmak_shuffle_key(&source.replace('A', "q")), None);
    let no_lcg = reordered("1234567", "32").replace(&cipher("4282663"), &cipher("4282664"));
    assert_eq!(extract_bmak_shuffle_key(&no_lcg), None);
    assert_eq!(
        extract_bmak_shuffle_key("const arbitrary = ['1234567','65793','4282663'];"),
        None
    );
}

#[test]
fn rejects_ambiguous_digit_one_mappings() {
    let source = legacy("1234567").replace(&format!("'{}'", cipher("1000")), "'Aqqq','Bqqq'");
    assert_eq!(extract_bmak_shuffle_key(&source), None);
}

#[test]
fn extracts_supported_xor_periods_with_controls_and_wrapping() {
    for period in [8, 9, 16, 20, 23, 31, 64] {
        for wrapping in [false, true] {
            assert_eq!(
                extract_bmak_ver(&version_table(VERSION, period, wrapping)).as_deref(),
                Some(VERSION),
                "period {period}, wrapping {wrapping}"
            );
        }
    }
}

#[test]
fn rejects_conflicting_versions_but_accepts_repeated_identical_tables() {
    let first = version_table(VERSION, 23, true);
    let second = version_table(OTHER_VERSION, 20, true);
    assert_eq!(extract_bmak_ver(&format!("{first}{second}")), None);
    assert_eq!(extract_bmak_ver(&format!("{second}{first}")), None);
    assert_eq!(
        extract_bmak_ver(&format!("{first}{first}")).as_deref(),
        Some(VERSION)
    );
}

#[test]
fn ignores_tables_inside_comments_strings_templates_and_regexes() {
    let tables = format!("{}{}", legacy("1234567"), version_table(VERSION, 23, true));
    let quoted = serde_json::to_string(&tables).unwrap();
    for source in [
        format!("/* {tables} */"),
        format!("// {tables}\n"),
        format!("const text = {quoted};"),
        format!("const text = `{tables}`;"),
        format!("const regex = /{tables}/;"),
        format!("function f() {{ return /{tables}/; }}"),
    ] {
        assert_eq!(extract_bmak_shuffle_key(&source), None, "{source}");
        assert_eq!(extract_bmak_ver(&source), None, "{source}");
    }
    let prefix = r#"const re = /['"\[\]\/]/g; const ratio = left / right;"#;
    assert_eq!(
        extract_bmak_shuffle_key(&format!("{prefix}{}", current("1234567"))),
        Some(1_234_567)
    );
    for newline in ["\n", "\r", "\r\n"] {
        assert_eq!(
            extract_bmak_shuffle_key(&format!(
                "// ignore {tables}{newline}{}",
                current("1234567")
            )),
            Some(1_234_567)
        );
    }
}

#[test]
fn ignores_regexes_after_control_statements_and_nested_templates() {
    let table = legacy("1234567");
    for source in [
        format!("if (ready) /{table}/.test(input);"),
        format!("while (ready) /{table}/.test(input);"),
        format!("if (ready) {{ work(); }} /{table}/.test(input);"),
        format!("const text = `outer ${{ `{table}` }}`;"),
    ] {
        assert_eq!(extract_bmak_shuffle_key(&source), None, "{source}");
    }
}

#[test]
fn distinguishes_array_literals_from_comma_expressions_in_property_access() {
    let array = numeric_table(&[
        "4095.000000",
        "2",
        "0",
        "34",
        "1000",
        "65535.000000",
        "65793",
        "4282663",
        "8388607.000000",
        "4294967295.000000",
        "3",
        "1234567",
    ]);
    assert_eq!(
        extract_bmak_shuffle_key(&format!("const property = object{array};")),
        None
    );
    assert_eq!(
        extract_bmak_shuffle_key(&format!("const nested = object[{array}];")),
        Some(1_234_567)
    );
}

#[test]
fn rejects_malformed_arrays_and_non_byte_xor_strings() {
    for source in ["['unterminated", "['a', x]", "[\"\\uD800\"]", "[\"\\xGG\"]"] {
        assert_eq!(extract_bmak_shuffle_key(source), None);
        assert_eq!(extract_bmak_ver(source), None);
    }
    assert_eq!(
        extract_bmak_shuffle_key(&format!("const broken = /{}", legacy("1234567"))),
        None
    );
    assert_eq!(
        extract_bmak_ver(&format!(
            "const unrelated = ['🙂','漢字'];{}",
            version_table(VERSION, 16, true)
        ))
        .as_deref(),
        Some(VERSION)
    );
}

#[test]
fn rejects_invalid_version_padding_and_unrelated_arrays() {
    let malformed = format!("{}B=", &VERSION[..42]); // Nonzero unused Base64 pad bits.
    assert_eq!(extract_bmak_ver(&version_table(&malformed, 23, true)), None);
    assert_eq!(
        extract_bmak_ver("const unrelated = ['hello', 'world', '1234567'];"),
        None
    );
}
