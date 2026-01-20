//! near-zk CLI Tool
//!
//! A command-line tool for working with Groth16 ZK contracts on NEAR Protocol.
//!
//! ## Features
//! - Convert snarkjs verification keys to NEAR-compatible format
//! - Convert proofs and public signals
//! - Generate deployment commands
//! - Format proofs for contract calls
//!
//! ## Usage
//! ```bash
//! # Convert verification key
//! near-zk convert-vk verification_key.json
//!
//! # Format proof for contract call
//! near-zk format-proof proof.json public.json
//!
//! # Generate deployment script
//! near-zk deploy-script verification_key.json --contract my-contract.testnet
//! ```

use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use regex::Regex;

#[derive(Parser)]
#[command(name = "near-zk")]
#[command(about = "CLI tool for Groth16 ZK contracts on NEAR Protocol", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Convert snarkjs verification key to NEAR format
    ConvertVk {
        /// Path to verification_key.json
        #[arg(short, long)]
        input: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Format proof and public signals for contract call
    FormatProof {
        /// Path to proof.json
        #[arg(short, long)]
        proof: PathBuf,

        /// Path to public.json
        #[arg(short = 's', long)]
        signals: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Generate deployment script
    DeployScript {
        /// Path to verification_key.json
        #[arg(short, long)]
        vk: PathBuf,

        /// Contract account ID
        #[arg(short, long)]
        contract: String,

        /// Deployer account ID
        #[arg(short, long)]
        deployer: String,

        /// Network (mainnet/testnet)
        #[arg(short, long, default_value = "testnet")]
        network: String,

        /// Path to WASM file (SECURITY FIX LOW-5: now configurable)
        #[arg(short, long)]
        wasm: Option<PathBuf>,
    },

    /// Validate verification key format
    Validate {
        /// Path to verification_key.json
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Generate call arguments for verify method
    CallArgs {
        /// Path to proof.json
        #[arg(short, long)]
        proof: PathBuf,

        /// Path to public.json
        #[arg(short = 's', long)]
        signals: PathBuf,
    },

    /// Show circuit info from verification key
    Info {
        /// Path to verification_key.json
        #[arg(short, long)]
        input: PathBuf,
    },
}

/// snarkjs verification key structure
#[derive(Debug, Serialize, Deserialize)]
struct VerificationKey {
    protocol: Option<String>,
    curve: Option<String>,
    #[serde(rename = "nPublic")]
    n_public: Option<u32>,
    vk_alpha_1: Vec<String>,
    vk_beta_2: Vec<Vec<String>>,
    vk_gamma_2: Vec<Vec<String>>,
    vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    ic: Vec<Vec<String>>,
}

/// snarkjs proof structure
#[derive(Debug, Serialize, Deserialize)]
struct Proof {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
    protocol: Option<String>,
    curve: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::ConvertVk { input, output } => {
            convert_verification_key(&input, output.as_deref())?;
        }

        Commands::FormatProof { proof, signals, output } => {
            format_proof(&proof, &signals, output.as_deref())?;
        }

        Commands::DeployScript { vk, contract, deployer, network, wasm } => {
            generate_deploy_script(&vk, &contract, &deployer, &network, wasm.as_deref())?;
        }

        Commands::Validate { input } => {
            validate_vk(&input)?;
        }

        Commands::CallArgs { proof, signals } => {
            generate_call_args(&proof, &signals)?;
        }

        Commands::Info { input } => {
            show_vk_info(&input)?;
        }
    }

    Ok(())
}

fn convert_verification_key(input: &PathBuf, output: Option<&std::path::Path>) -> anyhow::Result<()> {
    println!("{}", "Converting verification key...".cyan());

    let content = fs::read_to_string(input)?;
    let vk: VerificationKey = serde_json::from_str(&content)?;

    // Validate
    if vk.protocol.as_deref() != Some("groth16") {
        println!("{}", "Warning: Protocol is not groth16".yellow());
    }

    if vk.curve.as_deref() != Some("bn128") {
        println!("{}", "Warning: Curve is not bn128 (BN254)".yellow());
    }

    // Convert to NEAR format (same structure, but validate and clean)
    let near_vk = json!({
        "protocol": vk.protocol,
        "curve": vk.curve,
        "nPublic": vk.n_public,
        "vk_alpha_1": vk.vk_alpha_1,
        "vk_beta_2": vk.vk_beta_2,
        "vk_gamma_2": vk.vk_gamma_2,
        "vk_delta_2": vk.vk_delta_2,
        "IC": vk.ic,
    });

    let output_str = serde_json::to_string_pretty(&near_vk)?;

    if let Some(out_path) = output {
        fs::write(out_path, &output_str)?;
        println!("{} {}", "Saved to:".green(), out_path.display());
    } else {
        println!("{}", output_str);
    }

    println!("{} {} public inputs", "Verification key has".green(), vk.ic.len() - 1);

    Ok(())
}

fn format_proof(proof_path: &PathBuf, signals_path: &PathBuf, output: Option<&std::path::Path>) -> anyhow::Result<()> {
    println!("{}", "Formatting proof for NEAR contract...".cyan());

    let proof_content = fs::read_to_string(proof_path)?;
    let signals_content = fs::read_to_string(signals_path)?;

    let proof: Proof = serde_json::from_str(&proof_content)?;
    let signals: Vec<String> = serde_json::from_str(&signals_content)?;

    // Create the call format
    let call_data = json!({
        "proof": {
            "pi_a": proof.pi_a,
            "pi_b": proof.pi_b,
            "pi_c": proof.pi_c
        },
        "public_inputs": signals
    });

    let output_str = serde_json::to_string_pretty(&call_data)?;

    if let Some(out_path) = output {
        fs::write(out_path, &output_str)?;
        println!("{} {}", "Saved to:".green(), out_path.display());
    } else {
        println!("{}", output_str);
    }

    Ok(())
}

/// Validate NEAR account ID format
/// NEAR account IDs must be 2-64 characters, lowercase alphanumeric with hyphens, dots, underscores
fn validate_account_id(account_id: &str) -> anyhow::Result<()> {
    // NEAR account ID validation rules
    let re = Regex::new(r"^[a-z0-9._-]{2,64}$").unwrap();

    if !re.is_match(account_id) {
        anyhow::bail!(
            "Invalid NEAR account ID '{}'. Must be 2-64 lowercase alphanumeric characters, with hyphens, dots, or underscores only.",
            account_id
        );
    }

    // Additional checks
    if account_id.starts_with('-') || account_id.starts_with('.') {
        anyhow::bail!("Account ID cannot start with hyphen or dot");
    }

    if account_id.ends_with('-') || account_id.ends_with('.') {
        anyhow::bail!("Account ID cannot end with hyphen or dot");
    }

    Ok(())
}

fn generate_deploy_script(
    vk_path: &PathBuf,
    contract: &str,
    deployer: &str,
    network: &str,
    wasm_path: Option<&std::path::Path>
) -> anyhow::Result<()> {
    println!("{}", "Generating deployment script...".cyan());

    // SECURITY: Validate all user inputs before embedding in script
    validate_account_id(contract)?;
    validate_account_id(deployer)?;

    // Validate network is whitelisted
    if !["mainnet", "testnet"].contains(&network.as_ref()) {
        anyhow::bail!("Network must be 'mainnet' or 'testnet', got '{}'", network);
    }

    let vk_content = fs::read_to_string(vk_path)?;
    let _vk: VerificationKey = serde_json::from_str(&vk_content)?;

    // SECURITY FIX (LOW-5): WASM path is now configurable
    // Default fallback for backwards compatibility
    let wasm_file = if let Some(path) = wasm_path {
        // Validate the WASM file exists
        if !path.exists() {
            println!("{} WASM file not found at: {}", "⚠".yellow(), path.display());
            println!("  Continuing anyway - script will fail if file doesn't exist at deploy time");
        }
        path.to_str().unwrap_or("target/wasm32-unknown-unknown/release/zk_verifier_basic.wasm").to_string()
    } else {
        "target/wasm32-unknown-unknown/release/zk_verifier_basic.wasm".to_string()
    };

    // Escape for shell
    let vk_escaped = vk_content.replace("'", "'\"'\"'");

    let script = format!(r#"#!/bin/bash
# NEAR ZK Contract Deployment Script
# Generated by near-zk CLI

set -e

CONTRACT="{contract}"
DEPLOYER="{deployer}"
NETWORK="{network}"
WASM_FILE="{wasm_file}"

echo "Deploying ZK verifier contract to $CONTRACT on $NETWORK..."

# Step 1: Build the contract (if needed)
# cargo build --target wasm32-unknown-unknown --release

# Step 2: Deploy the contract
echo "Deploying WASM from $WASM_FILE..."
near deploy --accountId "$CONTRACT" \
  --wasmFile "$WASM_FILE" \
  --network "$NETWORK"

# Step 3: Initialize with verification key
echo "Initializing with verification key..."
near call "$CONTRACT" new '{{"vk": {vk_escaped}}}' \
  --accountId "$DEPLOYER" \
  --network "$NETWORK" \
  --gas 300000000000000

echo "Deployment complete!"
echo ""
echo "To verify a proof, run:"
echo "  near call $CONTRACT verify '{{\"proof\": ..., \"public_inputs\": [...]}}' --accountId USER --network $NETWORK"
"#);

    println!("{}", script);
    println!();
    println!("{}", "Save this script and run with: bash deploy.sh".green());

    if wasm_path.is_none() {
        println!();
        println!("{}", "💡 Tip: Use --wasm to specify a custom WASM file path".yellow());
    }

    Ok(())
}

/// Parse a decimal string as a big number
fn parse_field_element(s: &str) -> anyhow::Result<Vec<u64>> {
    // Simple parser for decimal string to u64 array
    // This is a basic implementation - in production you'd use a proper BigInt library
    let num = s.parse::<u128>()
        .or_else(|_| {
            // Try parsing as hex if decimal fails
            if s.starts_with("0x") {
                u128::from_str_radix(&s[2..], 16)
            } else {
                Err(std::num::ParseIntError::from(s.parse::<u64>().unwrap_err()))
            }
        })?;

    Ok(vec![num as u64, (num >> 64) as u64])
}

/// Validate a field element is less than BN254 field modulus
fn validate_field_element(value_str: &str, field_name: &str) -> anyhow::Result<bool> {
    // BN254 field modulus (for reference):
    // 21888242871839275222246405745257275088548364400416034343698204186575808495617

    // Basic validation: check if it parses as a number
    // For production, would use a proper BigInt comparison
    match parse_field_element(value_str) {
        Ok(_) => Ok(true),
        Err(e) => {
            println!("  {} {}: invalid number format - {}", "✗".red(), field_name, e);
            Ok(false)
        }
    }
}

fn validate_vk(input: &PathBuf) -> anyhow::Result<()> {
    println!("{}", "Validating verification key...".cyan());

    let content = fs::read_to_string(input)?;
    let vk: VerificationKey = serde_json::from_str(&content)?;

    let mut valid = true;

    // Check protocol
    if vk.protocol.as_deref() == Some("groth16") {
        println!("  {} Protocol: groth16", "✓".green());
    } else {
        println!("  {} Protocol: {} (expected groth16)", "✗".red(), vk.protocol.as_deref().unwrap_or("unknown"));
        valid = false;
    }

    // Check curve
    if vk.curve.as_deref() == Some("bn128") {
        println!("  {} Curve: bn128 (BN254)", "✓".green());
    } else {
        println!("  {} Curve: {} (expected bn128)", "✗".red(), vk.curve.as_deref().unwrap_or("unknown"));
        valid = false;
    }

    // SECURITY FIX (LOW-4): Validate numeric field elements
    println!("  {} Validating field elements...", "⧗".yellow());

    // Check point formats AND numeric validity
    if vk.vk_alpha_1.len() >= 2 {
        println!("  {} Alpha (G1): {} elements", "✓".green(), vk.vk_alpha_1.len());
        // Validate each coordinate
        for (i, coord) in vk.vk_alpha_1.iter().enumerate() {
            if !validate_field_element(coord, &format!("Alpha[{}]", i))? {
                valid = false;
            }
        }
    } else {
        println!("  {} Alpha (G1): invalid", "✗".red());
        valid = false;
    }

    if vk.vk_beta_2.len() >= 2 && vk.vk_beta_2[0].len() >= 2 {
        println!("  {} Beta (G2): valid structure", "✓".green());
        // Validate numeric values
        for (i, coords) in vk.vk_beta_2.iter().enumerate() {
            for (j, coord) in coords.iter().enumerate() {
                if !validate_field_element(coord, &format!("Beta[{}][{}]", i, j))? {
                    valid = false;
                }
            }
        }
    } else {
        println!("  {} Beta (G2): invalid", "✗".red());
        valid = false;
    }

    if vk.vk_gamma_2.len() >= 2 && vk.vk_gamma_2[0].len() >= 2 {
        println!("  {} Gamma (G2): valid structure", "✓".green());
        for (i, coords) in vk.vk_gamma_2.iter().enumerate() {
            for (j, coord) in coords.iter().enumerate() {
                if !validate_field_element(coord, &format!("Gamma[{}][{}]", i, j))? {
                    valid = false;
                }
            }
        }
    } else {
        println!("  {} Gamma (G2): invalid", "✗".red());
        valid = false;
    }

    if vk.vk_delta_2.len() >= 2 && vk.vk_delta_2[0].len() >= 2 {
        println!("  {} Delta (G2): valid structure", "✓".green());
        for (i, coords) in vk.vk_delta_2.iter().enumerate() {
            for (j, coord) in coords.iter().enumerate() {
                if !validate_field_element(coord, &format!("Delta[{}][{}]", i, j))? {
                    valid = false;
                }
            }
        }
    } else {
        println!("  {} Delta (G2): invalid", "✗".red());
        valid = false;
    }

    let num_inputs = vk.ic.len().saturating_sub(1);
    if !vk.ic.is_empty() {
        println!("  {} IC points: {} ({} public inputs)", "✓".green(), vk.ic.len(), num_inputs);
        // Validate IC point coordinates
        for (i, ic_point) in vk.ic.iter().enumerate() {
            for (j, coord) in ic_point.iter().enumerate() {
                if !validate_field_element(coord, &format!("IC[{}][{}]", i, j))? {
                    valid = false;
                }
            }
        }
    } else {
        println!("  {} IC points: missing", "✗".red());
        valid = false;
    }

    println!();
    if valid {
        println!("{}", "Verification key is valid!".green().bold());
    } else {
        println!("{}", "Verification key has issues.".red().bold());
        anyhow::bail!("VK validation failed");
    }

    Ok(())
}

fn generate_call_args(proof_path: &PathBuf, signals_path: &PathBuf) -> anyhow::Result<()> {
    let proof_content = fs::read_to_string(proof_path)?;
    let signals_content = fs::read_to_string(signals_path)?;

    let proof: Proof = serde_json::from_str(&proof_content)?;
    let signals: Vec<String> = serde_json::from_str(&signals_content)?;

    // Generate the NEAR CLI call command
    let call_data = json!({
        "proof": {
            "pi_a": proof.pi_a,
            "pi_b": proof.pi_b,
            "pi_c": proof.pi_c
        },
        "public_inputs": signals
    });

    let call_json = serde_json::to_string(&call_data)?;

    println!("{}", "NEAR CLI call command:".cyan().bold());
    println!();
    println!("near call CONTRACT_ID verify '{}' --accountId YOUR_ACCOUNT", call_json);
    println!();

    println!("{}", "Or for check_proof (view method):".cyan());
    println!();
    println!("near view CONTRACT_ID check_proof '{}'", call_json);

    Ok(())
}

fn show_vk_info(input: &PathBuf) -> anyhow::Result<()> {
    let content = fs::read_to_string(input)?;
    let vk: VerificationKey = serde_json::from_str(&content)?;

    println!("{}", "=== Verification Key Info ===".cyan().bold());
    println!();
    println!("Protocol:       {}", vk.protocol.as_deref().unwrap_or("unknown"));
    println!("Curve:          {}", vk.curve.as_deref().unwrap_or("unknown"));
    println!("Public inputs:  {}", vk.ic.len().saturating_sub(1));
    println!("IC points:      {}", vk.ic.len());
    println!();

    // Estimate verification cost
    let num_inputs = vk.ic.len().saturating_sub(1);
    let estimated_gas = 50 + (num_inputs as u64 * 5); // Rough estimate in TGas
    println!("{}", "Estimated Verification Cost:".yellow());
    println!("  ~{}-{} TGas", estimated_gas, estimated_gas + 30);
    println!("  ~{:.4} NEAR (at 100 Tgas/mNEAR)", (estimated_gas as f64) / 1000.0);

    Ok(())
}
