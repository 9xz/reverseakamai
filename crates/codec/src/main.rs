//! CLI for `akamai-codec`.
//!
//! ```text
//! akamai-codec abck   '<_abck>'
//! akamai-codec sensor '<sensor_data>' [--bm-sz '<bm_sz>'] [--sub N] [--shuffle N] [--recover LOW..HIGH]
//! akamai-codec pow    --token T --salt S --start-ts N --difficulty D [--rounds 10]
//! akamai-codec cpt    --timestamp N --nonce S --difficulty D [--rounds 10]
//! akamai-codec pixel  <seed-or-script-path>
//! akamai-codec script '<javascript-file>'
//! akamai-codec bench  '<input>' [--encode] [--repeat-to N] [--bm-sz '<bm_sz>'] [--sub N] [--shuffle N] [--iterations N]
//! akamai-codec vm     <blob-file> [--tables]
//! ```

use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use akamai_codec::abck::{Abck, WorkItem};
use akamai_codec::pixel::{endpoint_hash, seed_token, url_config_bits};
use akamai_codec::pow::{solve_in_sensor, solve_sec_cpt};
use akamai_codec::script::{analyze_script, report_json};
use akamai_codec::sensor::{
    DEFAULT_SUB_KEY, Envelope, bm_sz_seed, decode_body, encode_body, recover_v3_shuffle_key,
};
use akamai_codec::vm::{disassemble, permutation_tables, selector_keys};

const USAGE: &str = "\
usage: akamai-codec <subcommand> [options]

  abck   '<_abck>'
  sensor '<sensor_data>' [--bm-sz '<cookie>'] [--sub N] [--shuffle N] [--recover LOW..HIGH]
  pow    --token T --salt S --start-ts N --difficulty D [--rounds 10]
  cpt    --timestamp N --nonce S --difficulty D [--rounds 10]
  pixel  <seed-integer | script-url-path>
  script <javascript-file>
  bench  '<input>' [--encode] [--repeat-to N] [--bm-sz '<cookie>'] [--sub N] [--shuffle N] [--iterations N]
  vm     <bytecode-file> [--tables]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let Some((cmd, rest)) = args.split_first() else {
        println!("{USAGE}");
        return Ok(());
    };
    match cmd.as_str() {
        "-h" | "--help" => println!("{USAGE}"),
        "abck" => cmd_abck(rest)?,
        "sensor" => cmd_sensor(rest)?,
        "pow" => cmd_pow(rest)?,
        "cpt" => cmd_cpt(rest)?,
        "pixel" => cmd_pixel(rest)?,
        "script" => cmd_script(rest)?,
        "bench" => cmd_bench(rest)?,
        "vm" => cmd_vm(rest)?,
        other => return Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
    Ok(())
}

fn cmd_abck(args: &[String]) -> Result<(), String> {
    let raw = args.first().ok_or("abck needs a cookie value")?;
    let parsed = Abck::parse(raw);
    println!("style:      {:?}", parsed.style);
    println!("token:      {}", parsed.token());
    println!("state:      {:?}", parsed.state());
    println!("state len:  {}", parsed.state_blob_len().unwrap_or(0));
    let items = parsed.work_items().map_err(|e| e.to_string())?;
    println!("work items: {}", items.len());
    for item in items {
        println!("  {item:?}");
    }
    Ok(())
}

fn cmd_sensor(args: &[String]) -> Result<(), String> {
    let raw = args.first().ok_or("sensor needs a sensor_data string")?;
    let mut sub_key: Option<u32> = None;
    let mut shuffle_key: Option<u32> = None;
    let mut recover: Option<(u32, u32)> = None;
    let mut iter = args[1..].iter();
    while let Some(flag) = iter.next() {
        let val = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--bm-sz" => sub_key = Some(bm_sz_seed(val)),
            "--sub" => sub_key = Some(val.parse().map_err(|_| "bad --sub")?),
            "--shuffle" => shuffle_key = Some(val.parse().map_err(|_| "bad --shuffle")?),
            "--recover" => {
                let (lo, hi) = val.split_once("..").ok_or("--recover needs LOW..HIGH")?;
                recover = Some((
                    lo.parse().map_err(|_| "bad low")?,
                    hi.parse().map_err(|_| "bad high")?,
                ));
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let env = Envelope::parse(raw, 0).map_err(|e| e.to_string())?;
    let (v2_sub, v2_shuf) = env
        .v2_keys()
        .map(|(a, b)| (Some(a), Some(b)))
        .unwrap_or((None, None));
    let sub = sub_key.or(v2_sub).unwrap_or(DEFAULT_SUB_KEY);
    let mut shuf = shuffle_key.or(v2_shuf);
    let sep = env.separator();

    println!("version: {}", env.version);
    println!("header:  {:?}", env.header);
    println!("sub key: {sub}");

    if shuf.is_none()
        && let Some((lo, hi)) = recover
    {
        let unsub = decode_body(&env.ciphertext, sep, sub, None);
        let tok = env.header.get(5).map(String::as_str).unwrap_or_default();
        shuf = recover_v3_shuffle_key(&unsub, tok, lo, hi);
        println!("recovered shuffle key: {shuf:?}");
    }
    let plain = decode_body(&env.ciphertext, sep, sub, shuf);
    println!("---\n{plain}");
    Ok(())
}

fn cmd_pow(args: &[String]) -> Result<(), String> {
    let mut token = String::new();
    let mut salt = String::new();
    let mut start_ts = 0u64;
    let mut difficulty = 0u32;
    let mut rounds = 10u32;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let val = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--token" => token = val.clone(),
            "--salt" => salt = val.clone(),
            "--start-ts" => start_ts = val.parse().map_err(|_| "bad --start-ts")?,
            "--difficulty" => difficulty = val.parse().map_err(|_| "bad --difficulty")?,
            "--rounds" => rounds = val.parse().map_err(|_| "bad --rounds")?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let item = WorkItem {
        id: "0".to_owned(),
        salt,
        difficulty,
        delay_ms: 0,
        slice_ms: 1000,
        version: Some(2),
    };
    let answer =
        solve_in_sensor(&token, start_ts, &item, rounds, 5_000_000).map_err(|e| e.to_string())?;
    println!("{}", answer.to_wire());
    Ok(())
}

fn cmd_cpt(args: &[String]) -> Result<(), String> {
    let mut timestamp = 0u64;
    let mut nonce = String::new();
    let mut difficulty = 0u32;
    let mut rounds = 10u32;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let val = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--timestamp" => timestamp = val.parse().map_err(|_| "bad --timestamp")?,
            "--nonce" => nonce = val.clone(),
            "--difficulty" => difficulty = val.parse().map_err(|_| "bad --difficulty")?,
            "--rounds" => rounds = val.parse().map_err(|_| "bad --rounds")?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    let answers = solve_sec_cpt(timestamp, &nonce, difficulty, rounds, 10_000_000)
        .map_err(|e| e.to_string())?;
    for a in answers {
        println!("{a}");
    }
    Ok(())
}

fn cmd_pixel(args: &[String]) -> Result<(), String> {
    let input = args.first().ok_or("pixel needs a seed or URL path")?;
    if let Ok(seed) = input.parse::<u64>() {
        println!("endpoint: /akam/13/pixel_{}", endpoint_hash(seed));
        println!("t:        {}", seed_token(input));
    } else {
        println!("bits: {:?}", url_config_bits(input));
    }
    Ok(())
}

fn cmd_script(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("script needs a JavaScript file")?;
    if args.len() != 1 {
        return Err("script accepts exactly one JavaScript file".into());
    }
    let source = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let report = analyze_script(&source);
    println!(
        "{}",
        serde_json::to_string_pretty(&report_json(&report)).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn repeat_to_len(seed: &str, target_bytes: usize) -> String {
    if seed.is_empty() || target_bytes == 0 {
        return String::new();
    }
    let mut out = String::with_capacity(target_bytes + seed.len());
    while out.len() < target_bytes {
        out.push_str(seed);
    }
    if out.len() > target_bytes {
        let mut cut = target_bytes;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
    }
    out
}

fn cmd_bench(args: &[String]) -> Result<(), String> {
    let mut raw: Option<&str> = None;
    let mut encode = false;
    let mut repeat_to: Option<usize> = None;
    let mut sub_key: Option<u32> = None;
    let mut shuffle_key: Option<u32> = None;
    let mut iterations = 1_000u64;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--encode" {
            encode = true;
            continue;
        }
        if arg.starts_with("--") {
            let val = iter.next().ok_or_else(|| format!("{arg} needs a value"))?;
            match arg.as_str() {
                "--bm-sz" => sub_key = Some(bm_sz_seed(val)),
                "--sub" => sub_key = Some(val.parse().map_err(|_| "bad --sub")?),
                "--shuffle" => shuffle_key = Some(val.parse().map_err(|_| "bad --shuffle")?),
                "--repeat-to" => {
                    let target: usize = val.parse().map_err(|_| "bad --repeat-to")?;
                    if target == 0 {
                        return Err("--repeat-to must be greater than zero".into());
                    }
                    repeat_to = Some(target);
                }
                "--iterations" => {
                    iterations = val.parse().map_err(|_| "bad --iterations")?;
                    if iterations == 0 {
                        return Err("--iterations must be greater than zero".into());
                    }
                }
                other => return Err(format!("unknown flag {other:?}")),
            }
        } else if raw.is_none() {
            raw = Some(arg.as_str());
        } else {
            return Err(format!("unexpected positional argument {arg:?}"));
        }
    }
    let raw = raw.ok_or("bench needs an input string")?;
    if encode {
        let plain = match repeat_to {
            Some(target) => repeat_to_len(raw, target),
            None => raw.to_owned(),
        };
        let sub = sub_key.unwrap_or(DEFAULT_SUB_KEY);
        let shuf = shuffle_key.unwrap_or(70_010);
        let started = Instant::now();
        let mut output_bytes = 0;
        for _ in 0..iterations {
            output_bytes = black_box(encode_body(black_box(&plain), ':', sub, shuf)).len();
        }
        let seconds = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
        let total_bytes = iterations as u128 * plain.len() as u128;
        println!("operation:       encode");
        println!("iterations:      {iterations}");
        println!("input bytes:     {}", plain.len());
        println!("output bytes:    {output_bytes}");
        println!("elapsed:         {:.3} ms", seconds * 1_000.0);
        println!("encodes/sec:     {:.0}", iterations as f64 / seconds);
        println!(
            "encoded MB/sec:  {:.3}",
            total_bytes as f64 / seconds / 1_000_000.0
        );
        return Ok(());
    }

    let env = Envelope::parse(raw, 0).map_err(|e| e.to_string())?;
    let (v2_sub, v2_shuf) = env
        .v2_keys()
        .map(|(a, b)| (Some(a), Some(b)))
        .unwrap_or((None, None));
    let sub = sub_key.or(v2_sub).unwrap_or(DEFAULT_SUB_KEY);
    let shuf = shuffle_key.or(v2_shuf);
    let sep = env.separator();
    let ciphertext = match repeat_to {
        Some(target) => repeat_to_len(&env.ciphertext, target),
        None => env.ciphertext,
    };

    let started = Instant::now();
    let mut plaintext_bytes = 0;
    for _ in 0..iterations {
        plaintext_bytes = black_box(decode_body(black_box(&ciphertext), sep, sub, shuf)).len();
    }
    let seconds = started.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    let decoded_bytes = iterations as u128 * plaintext_bytes as u128;
    println!("operation:       decode");
    println!("iterations:      {iterations}");
    println!("plaintext bytes: {plaintext_bytes}");
    println!("elapsed:         {:.3} ms", seconds * 1_000.0);
    println!("decodes/sec:     {:.0}", iterations as f64 / seconds);
    println!(
        "decoded MB/sec:  {:.3}",
        decoded_bytes as f64 / seconds / 1_000_000.0
    );
    Ok(())
}

fn cmd_vm(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("vm needs a bytecode file")?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if args.iter().any(|a| a == "--tables") {
        for (i, table) in permutation_tables(&bytes).iter().enumerate() {
            println!("table {i}: {table:?}");
        }
        let keys = selector_keys(&bytes);
        if !keys.is_empty() {
            println!("keys:    {keys:?}");
        }
    } else {
        for inst in disassemble(&bytes) {
            println!("{:04x}  {:?}", inst.offset, inst.op);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_to_len_preserves_utf8_boundaries_and_target_size() {
        assert_eq!(repeat_to_len("abcd", 10), "abcdabcdab");
        assert_eq!(repeat_to_len("é", 3).len(), 2);
        assert_eq!(repeat_to_len("", 8), "");
    }

    #[test]
    fn bench_supports_encode_and_decode_modes() {
        let encode_args = vec![
            "{\"ver\":\"bench\"}".to_owned(),
            "--encode".to_owned(),
            "--repeat-to".to_owned(),
            "256".to_owned(),
            "--iterations".to_owned(),
            "5".to_owned(),
        ];
        assert!(cmd_bench(&encode_args).is_ok());

        let decode_args = vec![
            "2;2048;3360065;3683384;26,0,0,1,1,0;ABC".to_owned(),
            "--iterations".to_owned(),
            "5".to_owned(),
        ];
        assert!(cmd_bench(&decode_args).is_ok());
    }
}
