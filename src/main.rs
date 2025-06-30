use axum::{
    routing::{get, post},
    response::Json,
    Router,
    extract::Json as ExtractJson,
};
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Keypair, Signer, PublicKey, Verifier, Signature};
use rand::thread_rng;
use solana_program::{
    pubkey::Pubkey,
};
use spl_token::instruction;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose};

#[derive(Serialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintToRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CreateTokenResponse {
    Success {
        success: bool,
        data: CreateTokenData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[derive(Serialize)]
struct CreateTokenData {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SignMessageResponse {
    Success {
        success: bool,
        data: SignMessageData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum VerifyMessageResponse {
    Success {
        success: bool,
        data: VerifyMessageData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

async fn generate_keypair() -> Json<KeypairResponse> {
    let mut csprng = thread_rng();
    let keypair = Keypair::generate(&mut csprng);
    
    let pubkey = bs58::encode(keypair.public.to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    Json(KeypairResponse {
        success: true,
        data: KeypairData {
            pubkey,
            secret,
        },
    })
}

async fn create_token(ExtractJson(payload): ExtractJson<CreateTokenRequest>) -> Json<CreateTokenResponse> {
    let mint_authority = match Pubkey::from_str(&payload.mint_authority) {
        Ok(key) => key,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Invalid mint authority public key".to_string(),
        }),
    };
    
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Invalid mint public key".to_string(),
        }),
    };
    
    let instruction = match instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ) {
        Ok(instr) => instr,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Failed to create initialize mint instruction".to_string(),
        }),
    };
    
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    
    Json(CreateTokenResponse::Success {
        success: true,
        data: CreateTokenData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        },
    })
}

async fn mint_to(ExtractJson(payload): ExtractJson<MintToRequest>) -> Json<CreateTokenResponse> {
    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(key) => key,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Invalid mint public key".to_string(),
        }),
    };
    
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(key) => key,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Invalid destination public key".to_string(),
        }),
    };
    
    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(key) => key,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Invalid authority public key".to_string(),
        }),
    };
    
    let instruction = match instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(instr) => instr,
        Err(_) => return Json(CreateTokenResponse::Error {
            success: false,
            error: "Failed to create mint_to instruction".to_string(),
        }),
    };
    
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| AccountInfo {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();
    
    Json(CreateTokenResponse::Success {
        success: true,
        data: CreateTokenData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        },
    })
}

async fn sign_message(ExtractJson(payload): ExtractJson<SignMessageRequest>) -> Json<SignMessageResponse> {
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Json(SignMessageResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }

    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(SignMessageResponse::Error {
            success: false,
            error: "Invalid base58 secret key".to_string(),
        }),
    };
    
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return Json(SignMessageResponse::Error {
            success: false,
            error: "Invalid secret key format".to_string(),
        }),
    };
    
    let message_bytes = payload.message.as_bytes();
    let signature = keypair.sign(message_bytes);
    
    let signature_base64 = general_purpose::STANDARD.encode(signature.to_bytes());
    let public_key_base58 = bs58::encode(keypair.public.to_bytes()).into_string();
    
    Json(SignMessageResponse::Success {
        success: true,
        data: SignMessageData {
            signature: signature_base64,
            public_key: public_key_base58,
            message: payload.message,
        },
    })
}

async fn verify_message(ExtractJson(payload): ExtractJson<VerifyMessageRequest>) -> Json<VerifyMessageResponse> {
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Json(VerifyMessageResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }
    
    let signature_bytes = match general_purpose::STANDARD.decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Json(VerifyMessageResponse::Error {
            success: false,
            error: "Invalid base64 signature".to_string(),
        }),
    };
    
    let pubkey_bytes = match bs58::decode(&payload.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return Json(VerifyMessageResponse::Error {
            success: false,
            error: "Invalid base58 public key".to_string(),
        }),
    };
    
    let public_key = match PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return Json(VerifyMessageResponse::Error {
            success: false,
            error: "Invalid public key format".to_string(),
        }),
    };
    
    let signature = match Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return Json(VerifyMessageResponse::Error {
            success: false,
            error: "Invalid signature format".to_string(),
        }),
    };
    
    let message_bytes = payload.message.as_bytes();
    let is_valid = public_key.verify(message_bytes, &signature).is_ok();
    
    Json(VerifyMessageResponse::Success {
        success: true,
        data: VerifyMessageData {
            valid: is_valid,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    })
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, World! Prakash" }))
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_to))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
} 