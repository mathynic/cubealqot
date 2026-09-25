//! Fresh-process offline family certificate verifier.

use std::io::Read;

use cubealqot::family::admission::{
    CertificateVerification, parse_family_certificate, verify_family_certificate,
};

fn main() {
    let mut bytes = Vec::new();
    if let Err(error) = std::io::stdin().read_to_end(&mut bytes) {
        eprintln!("invalid input: {error}");
        std::process::exit(1);
    }
    let certificate = match parse_family_certificate(&bytes) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("REJECTED malformed certificate: {error}");
            std::process::exit(1);
        }
    };
    match verify_family_certificate(&certificate) {
        CertificateVerification::Verified(value) => {
            println!("VERIFIED status={:?}", value.certificate_status());
        }
        CertificateVerification::Inconclusive { reason } => {
            println!("INCONCLUSIVE reason={reason}");
            std::process::exit(2);
        }
        CertificateVerification::Rejected { reason } => {
            println!("REJECTED reason={reason}");
            std::process::exit(1);
        }
    }
}
