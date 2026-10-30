use std::collections::{HashMap, VecDeque};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};

use nonempty::NonEmpty;
use once_cell::sync::Lazy;
use pepper_sync::wallet::SyncMode;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_client_backend::data_api::error::Error as ZcbError;
use zcash_client_backend::zip321::TransactionRequest;
use zcash_keys::address::UnifiedAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::TxId;
use zingo_status::confirmation_status::ConfirmationStatus;
use zingolib::config::{ChainType, ClientConfig, WalletConfig, construct_indexer_uri};
use zingolib::data::proposal::{total_fee, ProportionalFeeProposal};
use zingolib::wallet::migration::ImmediateMigrationPlan;
use zingolib::data::receivers::{transaction_request_from_receivers, Receiver};
use zingolib::ensure_default_crypto_provider;
use zingolib::lightclient::LightClient;
use zingolib::wallet::error::ProposeSendError;
use zingolib::wallet::keys::unified::{ReceiverSelection, UnifiedKeyStore};
use zingolib::wallet::summary::data::{
    OutgoingNoteSummary, SendType, TransactionKind, TransactionSummary,
};
use zingolib::wallet::{
    PerformanceLevel, SyncConfig, TransparentAddressDiscovery, WalletSettings,
};
use zip32::AccountId;

pub type WalletResult<T> = Result<T, String>;

pub struct ClientSlot {
    pub client: LightClient,
    pub mnemonic: String,
    /// Quotes handed out by the propose calls, newest last, each under its
    /// own token. A quote stores nothing in the wallet and does not pause
    /// sync; signing re-proposes and checks the result against it.
    pub quotes: VecDeque<(String, Quote)>,
    /// Transactions signed by `create_transfer` and not yet broadcast, one
    /// entry per signing, in the order they must reach the network. A ZIP-320
    /// payment to a TEX address signs two: a shielded spend to an ephemeral
    /// transparent address, then the payment from it. `create_transfer`
    /// reports the last txid, and `broadcast_transfer` sends the whole entry.
    pub signed: VecDeque<NonEmpty<TxId>>,
}

/// What a propose call showed the user, kept so signing can refuse a
/// transaction that no longer matches it.
pub enum Quote {
    Send {
        request: TransactionRequest,
        proposal: ProportionalFeeProposal,
        /// Whether the proposal makes Sapling proofs, which need the Sapling
        /// parameters on disk before it is signed.
        proves_sapling: bool,
    },
    Ironwood {
        plan: ImmediateMigrationPlan,
    },
}

/// Enough for every quote a send screen can have open at once; older quotes
/// fall off and fail as unknown tokens.
const MAX_QUOTES: usize = 32;
static QUOTE_COUNTER: AtomicU64 = AtomicU64::new(0);

static DOCUMENT_DIR: Lazy<Mutex<Option<PathBuf>>> = Lazy::new(|| Mutex::new(None));
/// Each wallet has its own lock, so one wallet's network calls and proving
/// do not hold up the others. The map lock is held only to look a slot up.
static CLIENTS: Lazy<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<ClientSlot>>>>> =
    Lazy::new(|| tokio::sync::Mutex::new(HashMap::new()));

const IRONWOOD_MAINNET: u32 = 3_428_143;
const IRONWOOD_TESTNET: u32 = 4_134_000;

pub struct Addresses {
    pub unified_address: String,
    pub sapling_address: String,
    pub transparent_address: String,
}

pub struct Balance {
    pub transparent_available_zatoshi: String,
    pub transparent_total_zatoshi: String,
    pub sapling_available_zatoshi: String,
    pub sapling_total_zatoshi: String,
    pub orchard_available_zatoshi: String,
    pub orchard_total_zatoshi: String,
    pub ironwood_available_zatoshi: String,
    pub ironwood_total_zatoshi: String,
}

pub struct Transaction {
    pub raw_transaction_id: String,
    pub block_time_in_seconds: i64,
    pub mined_height: i64,
    pub value: String,
    pub fee: Option<String>,
    pub to_address: Option<String>,
    pub is_shielding: bool,
    pub is_expired: bool,
    pub memos: Vec<String>,
}

pub struct Poll {
    pub alias: String,
    pub status: String,
    pub scan_progress: f64,
    pub network_block_height: u32,
    pub balances: Balance,
    pub transactions: Vec<Transaction>,
}

async fn client_slot(alias: &str) -> WalletResult<Arc<tokio::sync::Mutex<ClientSlot>>> {
    CLIENTS
        .lock()
        .await
        .get(alias)
        .cloned()
        .ok_or_else(|| format!("wallet {alias} does not exist"))
}

/// Stops a slot taken out of the map, once any call still using it returns.
async fn shut_down(slot: Arc<tokio::sync::Mutex<ClientSlot>>) {
    let mut slot = slot.lock().await;
    let _ = slot.client.stop_sync();
    slot.client.go_offline().await;
    let _ = slot.client.shutdown_save_task().await;
}

fn chain_from_network(network: &str) -> WalletResult<ChainType> {
    ChainType::try_from(network).map_err(|e| e.to_string())
}

fn indexer_uri(host: &str, port: u32) -> WalletResult<http::Uri> {
    let raw = if host.contains("://") {
        host.to_string()
    } else {
        format!("https://{host}:{port}")
    };
    construct_indexer_uri(raw).map_err(|e| e.to_string())
}

fn wallet_settings() -> WalletSettings {
    WalletSettings {
        sync_config: SyncConfig {
            transparent_address_discovery: TransparentAddressDiscovery::default(),
            performance_level: PerformanceLevel::High,
            // The wallet keeps following the chain after it catches up.
            shutdown_on_completion: false,
        },
        min_confirmations: NonZeroU32::new(3).expect("3 is non-zero"),
    }
}

fn document_dir() -> WalletResult<PathBuf> {
    DOCUMENT_DIR
        .lock()
        .expect("document dir lock")
        .clone()
        .ok_or_else(|| "documentDirectory is not set".to_string())
}

fn zat_str(value: Option<zcash_protocol::value::Zatoshis>) -> String {
    value
        .map(|z| z.into_u64().to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn network_type(chain: ChainType) -> NetworkType {
    match chain {
        ChainType::Mainnet => NetworkType::Main,
        ChainType::Testnet => NetworkType::Test,
        ChainType::Regtest(_) => NetworkType::Regtest,
    }
}

fn encode_sapling_from_ua(chain: ChainType, encoded_ua: &str) -> WalletResult<String> {
    let ua = UnifiedAddress::decode(&chain, encoded_ua).map_err(|e| e.to_string())?;
    let sapling = ua
        .sapling()
        .ok_or_else(|| "unified address has no sapling receiver".to_string())?;
    Ok(ZcashAddress::from_sapling(network_type(chain), sapling.to_bytes()).encode())
}

fn json_string_field(value: &json::JsonValue, field: &str) -> String {
    value[field].as_str().unwrap_or("").to_string()
}

fn json_bool_field(value: &json::JsonValue, field: &str) -> bool {
    value[field].as_bool().unwrap_or(false)
}

pub fn set_document_directory(path: String) -> WalletResult<()> {
    std::fs::create_dir_all(&path).map_err(|e| e.to_string())?;
    let path = PathBuf::from(path);
    // The Sapling proving parameters are cached beside the wallet data, in
    // the writable location the host picks.
    crate::sapling_params::set_directory(path.join("sapling-params"))?;
    *DOCUMENT_DIR.lock().expect("document dir lock") = Some(path);
    Ok(())
}

/// Set once the Sapling parameter download has been started, so a sync that
/// keeps reporting a Sapling balance does not queue it again.
static SAPLING_PARAMS_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Starts the Sapling parameter download the first time a Sapling balance is
/// seen.
///
/// The parameters are ~50MB and are needed only to spend Sapling notes, so
/// they are fetched on the first receive rather than compiled in. Doing it
/// here means the download runs while the user is still looking at an
/// incoming transaction, long before they can ask to send it. Its outcome is
/// logged rather than surfaced: a failure here must not fail the poll, and
/// the spend path fetches again.
fn request_sapling_params_once(has_sapling: bool) {
    use std::sync::atomic::Ordering;
    if !has_sapling || SAPLING_PARAMS_REQUESTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tokio::spawn(async {
        match crate::sapling_params::fetch().await {
            Ok(()) => eprintln!("[zcash] sapling params ready"),
            Err(e) => {
                // Allow a later poll to try again.
                SAPLING_PARAMS_REQUESTED.store(false, Ordering::SeqCst);
                eprintln!("[zcash] sapling params fetch failed: {e}");
            }
        }
    });
}

pub async fn initialize(
    mnemonic_seed: String,
    birthday_height: u32,
    alias: String,
    network_name: String,
    default_host: String,
    default_port: u32,
    new_wallet: bool,
) -> WalletResult<()> {
    ensure_default_crypto_provider();
    let chain = chain_from_network(&network_name)?;
    let uri = indexer_uri(&default_host, default_port)?;
    let wallet_dir = document_dir()?.join(&alias);
    std::fs::create_dir_all(&wallet_dir).map_err(|e| e.to_string())?;
    let wallet_path = wallet_dir.join("zingo-wallet.dat");
    let exists = wallet_path.exists();

    let wallet_config = if exists && !new_wallet {
        WalletConfig::Read
    } else {
        WalletConfig::MnemonicPhrase {
            mnemonic_phrase: mnemonic_seed.clone(),
            no_of_accounts: NonZeroU32::new(1).expect("1 is non-zero"),
            birthday: birthday_height,
            wallet_settings: wallet_settings(),
        }
    };

    // A client still open on this wallet would keep saving to the file the
    // new one reads, so it is shut down first.
    let previous = CLIENTS.lock().await.remove(&alias);
    if let Some(previous) = previous {
        shut_down(previous).await;
    }

    let config = ClientConfig::builder()
        .set_wallet_dir(wallet_dir)
        .set_wallet_name("zingo-wallet.dat".to_string())
        .set_chain_type(chain)
        .set_indexer_uri(uri)
        .set_wallet_config(wallet_config)
        .build()
        .map_err(|e| e.to_string())?;

    let mut client = LightClient::new(config, new_wallet)
        .await
        .map_err(|e| e.to_string())?;
    client.save_task().await;
    client.sync().await.map_err(|e| e.to_string())?;

    CLIENTS.lock().await.insert(
        alias,
        Arc::new(tokio::sync::Mutex::new(ClientSlot {
            client,
            mnemonic: mnemonic_seed,
            quotes: VecDeque::new(),
            signed: VecDeque::new(),
        })),
    );
    Ok(())
}

pub async fn stop(alias: String) -> WalletResult<String> {
    let slot = CLIENTS.lock().await.remove(&alias);
    if let Some(slot) = slot {
        shut_down(slot).await;
    }
    Ok("OK".to_string())
}

pub async fn rescan(alias: String) -> WalletResult<()> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    slot.client.rescan().await.map_err(|e| e.to_string())
}

pub async fn derive_unified_address(alias: String) -> WalletResult<Addresses> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    let chain = slot.client.chain_type();

    let unified_json = slot.client.unified_addresses_json().await;
    let transparent_json = slot.client.transparent_addresses_json().await;

    let mut unified_address = String::new();
    let mut sapling_source = String::new();
    if let json::JsonValue::Array(addrs) = unified_json {
        for addr in addrs {
            let encoded = json_string_field(&addr, "encoded_address");
            if json_bool_field(&addr, "has_orchard") && unified_address.is_empty() {
                unified_address = encoded.clone();
            }
            if json_bool_field(&addr, "has_sapling") && sapling_source.is_empty() {
                sapling_source = encoded;
            }
        }
    }

    if unified_address.is_empty() {
        let (_id, ua) = slot
            .client
            .generate_unified_address(ReceiverSelection::orchard_only(), AccountId::ZERO)
            .await
            .map_err(|e| e.to_string())?;
        unified_address = ua.encode(&chain);
    }
    if sapling_source.is_empty() {
        let (_id, ua) = slot
            .client
            .generate_unified_address(ReceiverSelection::sapling_only(), AccountId::ZERO)
            .await
            .map_err(|e| e.to_string())?;
        sapling_source = ua.encode(&chain);
    }

    let mut transparent_address = String::new();
    if let json::JsonValue::Array(addrs) = transparent_json {
        if let Some(addr) = addrs.first() {
            transparent_address = json_string_field(addr, "encoded_address");
        }
    }
    if transparent_address.is_empty() {
        let (_id, taddr) = slot
            .client
            .generate_transparent_address(AccountId::ZERO, false)
            .await
            .map_err(|e| e.to_string())?;
        transparent_address = taddr.encode(&chain);
    }

    let sapling_address = encode_sapling_from_ua(chain, &sapling_source)?;

    Ok(Addresses {
        unified_address,
        sapling_address,
        transparent_address,
    })
}

pub async fn get_latest_network_height(alias: String) -> WalletResult<u32> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    let info = slot.client.info().await.map_err(|e| e.to_string())?;
    Ok(u32::try_from(info.latest_block_height).unwrap_or(u32::MAX))
}

pub async fn get_birthday_height(host: String, port: u32) -> WalletResult<u32> {
    ensure_default_crypto_provider();
    let uri = indexer_uri(&host, port)?;
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let config = ClientConfig::builder()
        .set_wallet_dir(dir.path().to_path_buf())
        .set_wallet_name("zingo-wallet.dat".to_string())
        .set_indexer_uri(uri)
        .set_wallet_config(WalletConfig::NewSeed {
            no_of_accounts: NonZeroU32::new(1).expect("1 is non-zero"),
            chain_height: 1,
            wallet_settings: wallet_settings(),
        })
        .build()
        .map_err(|e| e.to_string())?;
    let mut client = LightClient::new(config, true)
        .await
        .map_err(|e| e.to_string())?;
    let info = client.info().await.map_err(|e| e.to_string())?;
    Ok(u32::try_from(info.latest_block_height).unwrap_or(u32::MAX))
}

pub fn is_valid_address(address: String, network: String) -> bool {
    chain_from_network(&network)
        .is_ok_and(|chain| zcash_keys::address::Address::decode(&chain, &address).is_some())
}

pub fn derive_viewing_key(mnemonic_seed: String, network: String) -> WalletResult<String> {
    let chain = chain_from_network(&network)?;
    let mnemonic = bip0039::Mnemonic::from_phrase(&mnemonic_seed).map_err(|e| e.to_string())?;
    let keys = UnifiedKeyStore::new_from_mnemonic(chain, &mnemonic, AccountId::ZERO)
        .map_err(|e| e.to_string())?;
    let ufvk = UnifiedFullViewingKey::try_from(&keys).map_err(|e| e.to_string())?;
    ufvk.encode(&chain).map_err(|e| e.to_string())
}

pub fn ironwood_activation_height(network: String) -> Option<u32> {
    match network.as_str() {
        "mainnet" => Some(IRONWOOD_MAINNET),
        "testnet" => Some(IRONWOOD_TESTNET),
        _ => None,
    }
}

pub async fn poll(alias: String) -> WalletResult<Poll> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;

    // A continuous sync session keeps running after it reaches the tip, so
    // the session being alive does not mean the wallet is behind. The latest
    // published status says whether every scan range is scanned.
    let caught_up = slot
        .client
        .latest_sync_status()
        .is_some_and(|sync| sync.is_complete());
    let status = match slot.client.sync_mode() {
        SyncMode::Shutdown => "STOPPED",
        _ if caught_up => "SYNCED",
        SyncMode::Running | SyncMode::Paused => "SYNCING",
        SyncMode::NotRunning => "STOPPED",
    };

    let mut scan_progress = 0.0_f64;
    if let Some(sync) = slot.client.latest_sync_status() {
        if sync.total_outputs > 0 {
            scan_progress =
                sync.total_outputs_scanned as f64 * 100.0 / sync.total_outputs as f64;
        }
        if status == "SYNCED" {
            scan_progress = 100.0;
        }
    }

    let mut network_block_height = 0_u32;
    if let Ok(info) = slot.client.info().await {
        network_block_height = u32::try_from(info.latest_block_height).unwrap_or(0);
    }

    let balance = slot
        .client
        .account_balance(AccountId::ZERO)
        .await
        .map_err(|e| e.to_string())?;
    let balances = Balance {
        transparent_available_zatoshi: zat_str(balance.confirmed_transparent_balance),
        transparent_total_zatoshi: zat_str(balance.total_transparent_balance),
        sapling_available_zatoshi: zat_str(balance.confirmed_sapling_balance),
        sapling_total_zatoshi: zat_str(balance.total_sapling_balance),
        orchard_available_zatoshi: zat_str(balance.confirmed_orchard_balance),
        orchard_total_zatoshi: zat_str(balance.total_orchard_balance),
        ironwood_available_zatoshi: zat_str(balance.confirmed_ironwood_balance),
        ironwood_total_zatoshi: zat_str(balance.total_ironwood_balance),
    };

    request_sapling_params_once(
        balance
            .total_sapling_balance
            .is_some_and(|value| !value.is_zero()),
    );

    // Stored data that cannot be summarized fails the same way on every poll,
    // so it must not hold back the balances and status above.
    let mut transactions = Vec::new();
    if let Ok(summaries) = slot.client.transaction_summaries(false).await {
        for tx in summaries.iter() {
            let is_shielding = matches!(tx.kind, TransactionKind::Sent(SendType::Shield));
            let to_address = match tx.kind {
                TransactionKind::Sent(_) => sent_to_address(tx),
                TransactionKind::Received => None,
            };
            let mined_height = if let ConfirmationStatus::Confirmed(height) = tx.status {
                u32::from(height) as i64
            } else {
                0
            };
            let is_expired = matches!(tx.status, ConfirmationStatus::Failed(_));
            transactions.push(Transaction {
                raw_transaction_id: tx.txid.to_string(),
                block_time_in_seconds: i64::from(tx.datetime),
                mined_height,
                value: tx.value.to_string(),
                fee: tx.fee.map(|fee| fee.to_string()),
                to_address,
                is_shielding,
                is_expired,
                memos: memos(tx),
            });
        }
    }

    Ok(Poll {
        alias,
        status: status.to_string(),
        scan_progress,
        network_block_height,
        balances,
        transactions,
    })
}

/// The address a sent transaction paid. The outgoing notes and coins
/// include the wallet's own change, so an output the wallet also received is
/// skipped. A send to self has no other output and reports its own address.
fn sent_to_address(tx: &TransactionSummary) -> Option<String> {
    let shielded = [
        (&tx.outgoing_ironwood_notes, &tx.ironwood_notes),
        (&tx.outgoing_orchard_notes, &tx.orchard_notes),
        (&tx.outgoing_sapling_notes, &tx.sapling_notes),
    ];
    let address = |note: &OutgoingNoteSummary| {
        note.recipient_unified_address
            .clone()
            .unwrap_or_else(|| note.recipient.clone())
    };
    let external_note = shielded.iter().find_map(|(outgoing, owned)| {
        outgoing
            .iter()
            .find(|note| !owned.iter().any(|own| own.output_index == note.output_index))
            .map(address)
    });
    external_note
        .or_else(|| {
            tx.outgoing_transparent_coins
                .iter()
                .find(|coin| {
                    !tx.transparent_coins
                        .iter()
                        .any(|own| own.output_index == coin.output_index)
                })
                .map(|coin| coin.recipient.clone())
        })
        .or_else(|| {
            shielded
                .iter()
                .find_map(|(outgoing, _)| outgoing.first().map(address))
        })
}

/// The text memos on a transaction's outputs, each once. A note sent to self
/// appears as both an outgoing and a received note.
fn memos(tx: &TransactionSummary) -> Vec<String> {
    let received = tx
        .ironwood_notes
        .iter()
        .chain(&tx.orchard_notes)
        .chain(&tx.sapling_notes)
        .filter_map(|note| note.memo.as_ref());
    let sent = tx
        .outgoing_ironwood_notes
        .iter()
        .chain(&tx.outgoing_orchard_notes)
        .chain(&tx.outgoing_sapling_notes)
        .filter_map(|note| note.memo.as_ref());
    let mut memos: Vec<String> = Vec::new();
    for memo in sent.chain(received) {
        if !memo.is_empty() && !memos.contains(memo) {
            memos.push(memo.clone());
        }
    }
    memos
}

const STALE_QUOTE: &str = "the wallet changed since this quote; propose again";

/// Keeps a quote under a fresh token and returns the token.
fn store_quote(slot: &mut ClientSlot, quote: Quote) -> String {
    let token = format!("quote:{}", QUOTE_COUNTER.fetch_add(1, AtomicOrdering::Relaxed));
    if slot.quotes.len() >= MAX_QUOTES {
        slot.quotes.pop_front();
    }
    slot.quotes.push_back((token.clone(), quote));
    token
}

fn find_quote<'a>(slot: &'a ClientSlot, token: &str) -> WalletResult<&'a Quote> {
    slot.quotes
        .iter()
        .find(|(t, _)| t == token)
        .map(|(_, quote)| quote)
        .ok_or_else(|| "unknown proposal token".to_string())
}

fn take_quote(slot: &mut ClientSlot, token: &str) -> WalletResult<Quote> {
    let index = slot
        .quotes
        .iter()
        .position(|(t, _)| t == token)
        .ok_or_else(|| "unknown proposal token".to_string())?;
    Ok(slot.quotes.remove(index).expect("index in range").1)
}

/// True when two proposals spend the same inputs into the same outputs for
/// the same fee. Target and anchor heights are left out: they move with
/// every block, and a new block alone does not change what the user agreed
/// to.
fn same_spend(a: &ProportionalFeeProposal, b: &ProportionalFeeProposal) -> bool {
    a.proposed_version() == b.proposed_version()
        && a.steps().len() == b.steps().len()
        && a.steps().iter().zip(b.steps().iter()).all(|(x, y)| {
            x.transaction_request() == y.transaction_request()
                && x.payment_pools() == y.payment_pools()
                && x.transparent_inputs() == y.transparent_inputs()
                && x.shielded_inputs() == y.shielded_inputs()
                && x.prior_step_inputs() == y.prior_step_inputs()
                && x.balance() == y.balance()
                && x.is_shielding() == y.is_shielding()
        })
}

fn memo_bytes(memo: &str) -> WalletResult<MemoBytes> {
    MemoBytes::from_bytes(memo.as_bytes()).map_err(|_| "memo is too long".to_string())
}

fn optional_memo(memo: Option<String>) -> WalletResult<Option<MemoBytes>> {
    match memo {
        Some(value) if !value.is_empty() => Ok(Some(memo_bytes(&value)?)),
        _ => Ok(None),
    }
}

fn describe_error(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(inner) = source {
        parts.push(inner.to_string());
        source = inner.source();
    }
    parts.join(": ")
}

fn map_propose_send_error(err: ProposeSendError) -> String {
    match err {
        ProposeSendError::Proposal(ZcbError::InsufficientFunds {
            available,
            required,
        }) => format!(
            "Error while sending funds: Insufficient balance (have {}, need {} including fee)",
            available.into_u64(),
            required.into_u64()
        ),
        other => other.to_string(),
    }
}

async fn propose_request(alias: String, request: TransactionRequest) -> WalletResult<String> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    // A preview neither stores the proposal nor pauses sync, so a quote the
    // user abandons leaves the wallet syncing.
    let proposal = slot
        .client
        .preview_send(request.clone(), AccountId::ZERO)
        .await
        .map_err(map_propose_send_error)?;
    let fee = total_fee(&proposal).map_err(|e| e.to_string())?;
    let transaction_count = proposal.steps().len();
    let proves_sapling = zingolib::wallet::sapling_params::proves_sapling(&proposal);
    let token = store_quote(
        &mut slot,
        Quote::Send {
            request,
            proposal,
            proves_sapling,
        },
    );
    Ok(json::object! {
        "proposalBase64" => token,
        "transactionCount" => transaction_count,
        "totalFee" => fee.into_u64().to_string(),
    }
    .dump())
}

pub async fn propose_transfer(
    alias: String,
    zatoshi: String,
    to_address: String,
    memo: Option<String>,
) -> WalletResult<String> {
    let amount: u64 = zatoshi
        .parse()
        .map_err(|_| format!("invalid zatoshi amount {zatoshi}"))?;
    let recipient_address =
        ZcashAddress::try_from_encoded(&to_address).map_err(|e| e.to_string())?;
    let request = transaction_request_from_receivers(vec![Receiver {
        recipient_address,
        amount: Zatoshis::from_u64(amount).map_err(|e| e.to_string())?,
        memo: optional_memo(memo)?,
    }])
    .map_err(|e| e.to_string())?;
    propose_request(alias, request).await
}

fn spend_success_json(txid: String, raw: String) -> String {
    json::object! {
        "txId" => txid,
        "raw" => raw,
    }
    .dump()
}

pub async fn create_transfer(
    alias: String,
    proposal_base64: String,
    mnemonic_seed: String,
) -> WalletResult<String> {
    let slot = client_slot(&alias).await?;
    let proves_sapling = match find_quote(&*slot.lock().await, &proposal_base64)? {
        Quote::Send { proves_sapling, .. } => *proves_sapling,
        Quote::Ironwood { .. } => false,
    };
    // Fetched outside the lock: the download can take a while, and polls
    // must keep answering meanwhile.
    if proves_sapling {
        crate::sapling_params::fetch().await?;
    }

    let mut slot = slot.lock().await;
    if slot.mnemonic != mnemonic_seed {
        return Err("mnemonic mismatch".to_string());
    }

    match take_quote(&mut slot, &proposal_base64)? {
        Quote::Ironwood { plan } => {
            // Hold sync still across the re-plan and the migration, so the
            // notes the migration spends are the ones checked here.
            // quick_immediate_migration's own pause finds sync already
            // paused and leaves the resume to this guard.
            let _pause = slot.client.pause_sync_scoped().map_err(|e| e.to_string())?;
            let fresh = slot
                .client
                .plan_immediate_migration(AccountId::ZERO)
                .await
                .map_err(|e| e.to_string())?;
            if fresh != plan {
                return Err(STALE_QUOTE.to_string());
            }
            let summary = slot
                .client
                .quick_immediate_migration(AccountId::ZERO, true)
                .await
                .map_err(|e| describe_error(&e))?;
            let txid = summary
                .txids
                .first()
                .map(|txid| txid.to_string())
                .ok_or_else(|| "ironwood migration produced no transactions".to_string())?;
            Ok(spend_success_json(txid, String::new()))
        }
        Quote::Send {
            request, proposal, ..
        } => {
            // Storing the proposal pauses sync until it is calculated or
            // cleared, so the wallet cannot shift between this check and
            // the signing.
            let fresh = slot
                .client
                .propose_send(request, AccountId::ZERO)
                .await
                .map_err(map_propose_send_error)?;
            if !same_spend(&fresh, &proposal) {
                slot.client.clear_proposal().await;
                return Err(STALE_QUOTE.to_string());
            }
            let txids = slot
                .client
                .calculate_stored_proposal()
                .await
                .map_err(|e| describe_error(&e))?;
            // The last transaction pays the recipient; any before it fund
            // it (the ephemeral step of a TEX payment).
            let txid = *txids.last();
            if slot.signed.len() >= MAX_QUOTES {
                slot.signed.pop_front();
            }
            slot.signed.push_back(txids);
            let raw = {
                let wallet = slot.client.wallet().read().await;
                let transaction = wallet
                    .wallet_transactions
                    .get(&txid)
                    .ok_or_else(|| format!("signed tx {txid} missing from wallet"))?;
                let mut bytes = Vec::new();
                transaction
                    .transaction()
                    .write(&mut bytes)
                    .map_err(|e| e.to_string())?;
                hex::encode(bytes)
            };
            Ok(spend_success_json(txid.to_string(), raw))
        }
    }
}

pub async fn broadcast_transfer(alias: String, txid: String) -> WalletResult<String> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    let parsed = {
        let wallet = slot.client.wallet().read().await;
        wallet
            .wallet_transactions
            .keys()
            .find(|id| id.to_string() == txid)
            .copied()
            .ok_or_else(|| format!("unknown txid {txid}"))?
    };
    // Every transaction from the signing that produced this txid goes out,
    // in order, so a TEX payment's ephemeral step is followed by the payment.
    let txids = match slot.signed.iter().position(|ids| *ids.last() == parsed) {
        Some(index) => slot.signed.remove(index).expect("index in range"),
        None => NonEmpty::new(parsed),
    };
    let sent = slot
        .client
        .transmit_calculated(txids)
        .await
        .map_err(|e| describe_error(&e))?;
    Ok(sent.last().to_string())
}

pub async fn shield_funds(
    alias: String,
    seed: String,
    _memo: String,
    threshold: String,
) -> WalletResult<String> {
    let threshold_zats: u64 = threshold
        .parse()
        .map_err(|_| format!("invalid shield threshold {threshold}"))?;
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    if slot.mnemonic != seed {
        return Err("mnemonic mismatch".to_string());
    }

    let balance = slot
        .client
        .account_balance(AccountId::ZERO)
        .await
        .map_err(|e| e.to_string())?;
    let transparent = balance
        .confirmed_transparent_balance
        .map(|z| z.into_u64())
        .unwrap_or(0);
    if transparent < threshold_zats {
        return Err("transparent balance below shield threshold".to_string());
    }

    slot.client
        .propose_shield(AccountId::ZERO)
        .await
        .map_err(|e| describe_error(&e))?;
    let txids = slot
        .client
        .send_stored_proposal(true)
        .await
        .map_err(|e| describe_error(&e))?;
    Ok(txids.first().to_string())
}

pub async fn propose_orchard_to_ironwood_migration(alias: String) -> WalletResult<String> {
    let slot = client_slot(&alias).await?;
    let mut slot = slot.lock().await;
    let plan = slot
        .client
        .plan_immediate_migration(AccountId::ZERO)
        .await
        .map_err(|e| e.to_string())?;
    if plan.is_empty() {
        return Err("no spendable Orchard notes to migrate".to_string());
    }
    let amount = plan.migrated.to_string();
    let fee = plan.fee.to_string();
    let token = store_quote(&mut slot, Quote::Ironwood { plan });
    Ok(json::object! {
        "amountZatoshi" => amount,
        "feeZatoshi" => fee,
        "proposalBase64" => token,
    }
    .dump())
}

pub async fn propose_fulfilling_payment_uri(
    alias: String,
    payment_uri: String,
) -> WalletResult<String> {
    let request = TransactionRequest::from_uri(&payment_uri).map_err(|e| e.to_string())?;
    propose_request(alias, request).await
}

pub async fn emit_existing_transactions(_alias: String) -> WalletResult<()> {
    Ok(())
}
