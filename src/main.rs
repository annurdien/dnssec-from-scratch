mod crypto;
mod lab;
mod nsec;
mod rdata;
mod resolver;
mod transport;
mod wire;

use std::net::SocketAddr;
use std::process::ExitCode;

use lab::{run_all_lab_scenarios, LabMode, LocalLab};
use rdata::{parse_qtype, type_name, TYPE_A};
use resolver::{walk_nsec_zone, DnssecResolver, SecurityStatus, ValidationResult};
use transport::DnsTransport;
use wire::{rcode_name, DnsName};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    match args[0].as_str() {
        "verify" => cmd_verify(&args[1..]),
        "walk-nsec" => cmd_walk_nsec(&args[1..]),
        "demo" => cmd_demo(),
        "lab-walk" => cmd_lab_walk(),
        "lab-once" => cmd_lab_once(&args[1..]),
        other => {
            eprintln!("unknown subcommand: {other}\n");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "dnssec-from-scratch: standalone DNSSEC chain-of-trust validator\n\
         \n\
         USAGE:\n\
         \tdnssec-from-scratch verify <domain> [qtype] [--tcp] [--root <ip:port>]\n\
         \tdnssec-from-scratch walk-nsec <zone> --server <ip:port> [--max <n>]\n\
         \tdnssec-from-scratch demo\n\
         \tdnssec-from-scratch lab-walk\n\
         \tdnssec-from-scratch lab-once <mode> [domain]\n\
         \n\
         LAB MODES:\n\
         \tvalid | tamper-ip | strip-rrsig | expired-sig | bad-ds | strip-ds | unsigned | nsec3\n\
         \n\
         EXAMPLES:\n\
         \tdnssec-from-scratch verify iana.org A\n\
         \tdnssec-from-scratch verify cloudflare.com A\n\
         \tdnssec-from-scratch verify dnssec-failed.org A\n\
         \tdnssec-from-scratch verify nonexistent.iana.org A\n\
         \tdnssec-from-scratch demo"
    );
}

fn cmd_verify(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("error: verify requires a <domain> argument");
        return ExitCode::FAILURE;
    }

    let domain = match DnsName::parse_str(&args[0]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("invalid domain: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut qtype = TYPE_A;
    let mut resolver = DnssecResolver::default();
    let mut i = 1usize;

    while i < args.len() {
        match args[i].as_str() {
            "--tcp" => {
                resolver.transport.force_tcp = true;
                i += 1;
            }
            "--root" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --root requires <ip:port>");
                    return ExitCode::FAILURE;
                }
                match args[i + 1].parse::<SocketAddr>() {
                    Ok(addr) => resolver.root_servers = vec![addr],
                    Err(e) => {
                        eprintln!("invalid --root socket address: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                i += 2;
            }
            token if !token.starts_with("--") && i == 1 => {
                match parse_qtype(token) {
                    Ok(qt) => qtype = qt,
                    Err(e) => {
                        eprintln!("invalid qtype: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                i += 1;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    let result = resolver.resolve(&domain, qtype);
    print_result(&result);

    match result.status {
        SecurityStatus::Secure | SecurityStatus::Insecure => ExitCode::SUCCESS,
        SecurityStatus::Bogus => ExitCode::from(2),
    }
}

fn cmd_walk_nsec(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("error: walk-nsec requires <zone> --server <ip:port>");
        return ExitCode::FAILURE;
    }
    let zone = match DnsName::parse_str(&args[0]) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("invalid zone: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut server: Option<SocketAddr> = None;
    let mut max_steps = 15usize;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --server requires <ip:port>");
                    return ExitCode::FAILURE;
                }
                server = match args[i + 1].parse::<SocketAddr>() {
                    Ok(addr) => Some(addr),
                    Err(e) => {
                        eprintln!("invalid --server address: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                i += 2;
            }
            "--max" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --max requires a number");
                    return ExitCode::FAILURE;
                }
                max_steps = match args[i + 1].parse::<usize>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("invalid --max value: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    let Some(server_addr) = server else {
        eprintln!("error: --server <ip:port> is required");
        return ExitCode::FAILURE;
    };

    match walk_nsec_zone(&zone, server_addr, max_steps, &DnsTransport::default()) {
        Ok(entries) => {
            println!("NSEC zone walk for {zone} against {server_addr}:");
            for (idx, (owner, next, types)) in entries.iter().enumerate() {
                let tnames: Vec<String> = types.iter().map(|&t| type_name(t)).collect();
                println!("  {}. {} -> {} [{}]", idx + 1, owner, next, tnames.join(" "));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("NSEC walk failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_demo() -> ExitCode {
    println!("Running local DNSSEC tampering and negative-proof lab (ECDSA P-256 over loopback UDP/TCP)\n");
    match run_all_lab_scenarios() {
        Ok(results) => {
            for (idx, (label, _expected, res)) in results.iter().enumerate() {
                let tag = status_label(&res.status);
                println!("{}. [{tag}] {label}", idx + 1);
                println!("   summary: {}", res.summary);
                for ans in &res.answers {
                    println!("   answer:  {} {} {}", ans.name, type_name(ans.rtype), ans.rdata);
                }
            }
            println!("\nAll {} scenarios matched their expected cryptographic outcome.", results.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("lab demo failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_lab_walk() -> ExitCode {
    let lab = match LocalLab::start(LabMode::Valid) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed starting local lab: {e}");
            return ExitCode::FAILURE;
        }
    };
    let zone = DnsName::parse_str("lab.test.").unwrap();
    let res = walk_nsec_zone(&zone, lab.leaf_addr, 20, &DnsTransport::default());
    lab.stop();

    match res {
        Ok(entries) => {
            println!("Walking local NSEC-signed zone lab.test. starting from apex:");
            for (idx, (owner, next, types)) in entries.iter().enumerate() {
                let tnames: Vec<String> = types.iter().map(|&t| type_name(t)).collect();
                println!("  {}. {} -> {} [{}]", idx + 1, owner, next, tnames.join(" "));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("lab NSEC walk failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_lab_once(args: &[String]) -> ExitCode {
    if args.is_empty() {
        eprintln!("error: lab-once requires <mode> [domain]");
        return ExitCode::FAILURE;
    }
    let mode = match LabMode::parse(&args[0]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let target = args.get(1).map(|s| s.as_str()).unwrap_or("api.lab.test.");
    let qname = match DnsName::parse_str(target) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("invalid domain: {e}");
            return ExitCode::FAILURE;
        }
    };

    let lab = match LocalLab::start(mode) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed starting lab: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "Local lab mode={} (root={}, leaf={})\n",
        mode.name(),
        lab.root_addr,
        lab.leaf_addr
    );
    let result = lab.resolver().resolve(&qname, TYPE_A);
    lab.stop();
    print_result(&result);

    match result.status {
        SecurityStatus::Secure | SecurityStatus::Insecure => ExitCode::SUCCESS,
        SecurityStatus::Bogus => ExitCode::from(2),
    }
}

fn status_label(status: &SecurityStatus) -> &'static str {
    match status {
        SecurityStatus::Secure => "SECURE",
        SecurityStatus::Insecure => "INSECURE",
        SecurityStatus::Bogus => "BOGUS",
    }
}

fn print_result(res: &ValidationResult) {
    for line in &res.trace {
        println!("{line}");
    }
    println!();
    println!("STATUS:  {}", status_label(&res.status));
    println!(
        "QUERY:   {} {} (rcode={})",
        res.qname,
        type_name(res.qtype),
        rcode_name(res.rcode)
    );
    println!("SUMMARY: {}", res.summary);
    if !res.answers.is_empty() {
        println!("ANSWERS:");
        for rr in &res.answers {
            println!("  {}  {}  IN  {}  {}", rr.name, rr.ttl, type_name(rr.rtype), rr.rdata);
        }
    }
}
