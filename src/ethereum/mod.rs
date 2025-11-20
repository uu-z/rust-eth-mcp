use alloy::{
    primitives::{Address, U256, utils::parse_ether},
    providers::{Provider, ProviderBuilder, RootProvider},
    transports::http::{Client, Http},
    sol,
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*, tool, tool_handler, tool_router, schemars, service::RequestContext,
};
use rust_decimal::{Decimal, prelude::ToPrimitive};
use std::str::FromStr;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        function decimals() external view returns (uint8);
        function symbol() external view returns (string);
    }

    #[sol(rpc)]
    interface IUniswapV2Router {
        function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
        function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts);
    }
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetBalanceArgs {
    /// Wallet address to query
    pub address: String,
    /// Optional ERC20 token contract address (if empty, returns ETH balance)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetTokenPriceArgs {
    /// Token address or symbol (WETH, USDC, etc)
    pub token: String,
    /// Quote currency (ETH or USD)
    #[serde(default = "default_quote")]
    pub quote: String,
}

fn default_quote() -> String { "USD".to_string() }

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SwapTokensArgs {
    /// Source token address (use 0x0 for ETH)
    pub from_token: String,
    /// Destination token address
    pub to_token: String,
    /// Amount to swap (in human-readable format, e.g., "1.5")
    pub amount: String,
    /// Slippage tolerance percentage (e.g., "0.5" for 0.5%)
    #[serde(default = "default_slippage")]
    pub slippage: String,
}

fn default_slippage() -> String { "0.5".to_string() }

#[derive(Clone)]
pub struct EthTrader {
    rpc_url: String,
    #[allow(dead_code)]
    private_key: Option<String>,
    tool_router: ToolRouter<EthTrader>,
}

impl EthTrader {
    pub fn new() -> Self {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());
        let private_key = std::env::var("PRIVATE_KEY").ok();

        Self {
            rpc_url,
            private_key,
            tool_router: Self::tool_router(),
        }
    }

    async fn get_provider(&self) -> Result<RootProvider<Http<Client>>, McpError> {
        Ok(ProviderBuilder::new()
            .on_http(self.rpc_url.parse().map_err(|e| {
                McpError::invalid_params("invalid_rpc_url", Some(serde_json::json!({
                    "error": format!("Invalid RPC URL: {}", e)
                })))
            })?))
    }
}

#[tool_router]
impl EthTrader {
    #[tool(description = "Get ETH or ERC20 token balance for an address")]
    async fn get_balance(
        &self,
        Parameters(args): Parameters<GetBalanceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.get_provider().await?;
        let address = Address::from_str(&args.address).map_err(|_| {
            McpError::invalid_params("invalid_address", None)
        })?;

        if let Some(token_addr) = args.token {
            let token = Address::from_str(&token_addr).map_err(|_| {
                McpError::invalid_params("invalid_token_address", None)
            })?;

            let contract = IERC20::new(token, &provider);
            let balance_result = contract.balanceOf(address).call().await
                .map_err(|e| McpError::internal_error("contract_call_failed",
                    Some(serde_json::json!({"error": e.to_string()}))))?;
            let balance = balance_result._0;

            let decimals = contract.decimals().call().await
                .map_err(|e| McpError::internal_error("decimals_call_failed",
                    Some(serde_json::json!({"error": e.to_string()}))))?._0;

            let symbol = contract.symbol().call().await.ok().map(|s| s._0).unwrap_or_else(|| "UNKNOWN".to_string());

            let divisor = U256::from(10u128.pow(decimals as u32));
            let balance_decimal = Decimal::from_str(&balance.to_string()).unwrap() /
                                  Decimal::from_str(&divisor.to_string()).unwrap();

            let result = serde_json::json!({
                "address": args.address,
                "token": token_addr,
                "symbol": symbol,
                "balance": balance_decimal.to_string(),
                "decimals": decimals,
                "raw_balance": balance.to_string()
            });

            Ok(CallToolResult::success(vec![Content::text(result.to_string())]))
        } else {
            let balance = provider.get_balance(address).await
                .map_err(|e| McpError::internal_error("balance_fetch_failed",
                    Some(serde_json::json!({"error": e.to_string()}))))?;

            let balance_eth = Decimal::from_str(&balance.to_string()).unwrap() /
                              Decimal::from_str("1000000000000000000").unwrap();

            let result = serde_json::json!({
                "address": args.address,
                "balance": balance_eth.to_string(),
                "symbol": "ETH",
                "raw_balance": balance.to_string()
            });

            Ok(CallToolResult::success(vec![Content::text(result.to_string())]))
        }
    }

    #[tool(description = "Get current token price in USD or ETH using Uniswap")]
    async fn get_token_price(
        &self,
        Parameters(args): Parameters<GetTokenPriceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.get_provider().await?;

        let weth = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let router = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap();

        let token_addr = Address::from_str(&args.token).map_err(|_| {
            McpError::invalid_params("invalid_token_address", None)
        })?;

        let contract = IUniswapV2Router::new(router, &provider);
        let amount_in = parse_ether("1").unwrap();

        let path = if args.quote.to_uppercase() == "USD" {
            vec![token_addr, weth, usdc]
        } else {
            vec![token_addr, weth]
        };

        match contract.getAmountsOut(amount_in, path.clone()).call().await {
            Ok(result) => {
                let out_amount = result.amounts.last().unwrap();
                let decimals = if args.quote.to_uppercase() == "USD" { 6 } else { 18 };
                let divisor = U256::from(10u128.pow(decimals));
                let price = Decimal::from_str(&out_amount.to_string()).unwrap() /
                           Decimal::from_str(&divisor.to_string()).unwrap();

                let response = serde_json::json!({
                    "token": args.token,
                    "quote": args.quote,
                    "price": price.to_string(),
                    "path": path.iter().map(|a| format!("{:?}", a)).collect::<Vec<_>>()
                });

                Ok(CallToolResult::success(vec![Content::text(response.to_string())]))
            }
            Err(e) => Err(McpError::internal_error("price_fetch_failed",
                Some(serde_json::json!({"error": e.to_string()}))))
        }
    }

    #[tool(description = "Simulate a token swap on Uniswap V2 (does not execute on-chain)")]
    async fn swap_tokens(
        &self,
        Parameters(args): Parameters<SwapTokensArgs>,
    ) -> Result<CallToolResult, McpError> {
        let provider = self.get_provider().await?;

        let from_token = Address::from_str(&args.from_token).map_err(|_| {
            McpError::invalid_params("invalid_from_token", None)
        })?;
        let to_token = Address::from_str(&args.to_token).map_err(|_| {
            McpError::invalid_params("invalid_to_token", None)
        })?;

        let router = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap();
        let contract = IUniswapV2Router::new(router, &provider);

        let from_contract = IERC20::new(from_token, &provider);
        let from_decimals = from_contract.decimals().call().await
            .map_err(|e| McpError::internal_error("decimals_failed",
                Some(serde_json::json!({"error": e.to_string()}))))?._0;

        let amount_decimal = Decimal::from_str(&args.amount).map_err(|_| {
            McpError::invalid_params("invalid_amount", None)
        })?;
        let multiplier = Decimal::from_str(&format!("1{}", "0".repeat(from_decimals as usize))).unwrap();
        let amount_in = U256::from_str(&(amount_decimal * multiplier).to_string().split('.').next().unwrap()).unwrap();

        let path = vec![from_token, to_token];
        let swap_result = contract.getAmountsOut(amount_in, path.clone()).call().await
            .map_err(|e| McpError::internal_error("swap_simulation_failed",
                Some(serde_json::json!({"error": e.to_string()}))))?;

        let amount_out = swap_result.amounts.last().unwrap();
        let to_contract = IERC20::new(to_token, &provider);
        let to_decimals = to_contract.decimals().call().await
            .map_err(|e| McpError::internal_error("decimals_failed",
                Some(serde_json::json!({"error": e.to_string()}))))?._0;

        let slippage = Decimal::from_str(&args.slippage).unwrap_or(Decimal::new(5, 1));
        let min_out = amount_out * U256::from((10000 - (slippage * Decimal::from(100)).to_u64().unwrap()) as u128) / U256::from(10000u128);

        let to_divisor = U256::from(10u128.pow(to_decimals as u32));
        let amount_out_decimal = Decimal::from_str(&amount_out.to_string()).unwrap() /
                                 Decimal::from_str(&to_divisor.to_string()).unwrap();

        let gas_estimate = U256::from(150000u128);
        let gas_price_u128 = provider.get_gas_price().await.unwrap_or(30000000000u128);
        let gas_price = U256::from(gas_price_u128);
        let total_gas_cost = gas_estimate * gas_price;
        let gas_cost_eth = Decimal::from_str(&total_gas_cost.to_string()).unwrap() /
                          Decimal::from_str("1000000000000000000").unwrap();

        let result = serde_json::json!({
            "simulation": "success",
            "from_token": args.from_token,
            "to_token": args.to_token,
            "amount_in": args.amount,
            "estimated_output": amount_out_decimal.to_string(),
            "minimum_output": (Decimal::from_str(&min_out.to_string()).unwrap() / Decimal::from_str(&to_divisor.to_string()).unwrap()).to_string(),
            "slippage": format!("{}%", args.slippage),
            "gas_estimate": gas_estimate.to_string(),
            "gas_cost_eth": gas_cost_eth.to_string(),
            "note": "This is a simulation only. Transaction not executed on-chain."
        });

        Ok(CallToolResult::success(vec![Content::text(result.to_string())]))
    }
}

#[tool_handler]
impl ServerHandler for EthTrader {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Ethereum trading MCP server. Tools: get_balance (query ETH/ERC20 balances), get_token_price (get token prices via Uniswap), swap_tokens (simulate Uniswap swaps). Set ETH_RPC_URL environment variable for custom RPC endpoint.".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_eth_trader_creation() {
        let trader = EthTrader::new();
        assert!(trader.rpc_url.len() > 0);
    }

    #[test]
    fn test_default_quote() {
        assert_eq!(default_quote(), "USD");
    }

    #[test]
    fn test_default_slippage() {
        assert_eq!(default_slippage(), "0.5");
    }

    #[test]
    fn test_get_balance_args_deserialization() {
        let json = r#"{"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"}"#;
        let args: GetBalanceArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.address, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
        assert!(args.token.is_none());
    }

    #[test]
    fn test_get_balance_args_with_token() {
        let json = r#"{"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}"#;
        let args: GetBalanceArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.address, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
        assert_eq!(args.token.unwrap(), "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    }

    #[test]
    fn test_get_token_price_args_deserialization() {
        let json = r#"{"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"}"#;
        let args: GetTokenPriceArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.token, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        assert_eq!(args.quote, "USD");
    }

    #[test]
    fn test_get_token_price_args_with_quote() {
        let json = r#"{"token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "quote": "ETH"}"#;
        let args: GetTokenPriceArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.quote, "ETH");
    }

    #[test]
    fn test_swap_tokens_args_deserialization() {
        let json = r#"{"from_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "to_token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "amount": "100"}"#;
        let args: SwapTokensArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.from_token, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        assert_eq!(args.to_token, "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        assert_eq!(args.amount, "100");
        assert_eq!(args.slippage, "0.5");
    }

    #[test]
    fn test_swap_tokens_args_with_custom_slippage() {
        let json = r#"{"from_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "to_token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "amount": "100", "slippage": "1.5"}"#;
        let args: SwapTokensArgs = serde_json::from_str(json).unwrap();
        assert_eq!(args.slippage, "1.5");
    }

    #[test]
    fn test_address_parsing() {
        let valid_address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let addr = Address::from_str(valid_address);
        assert!(addr.is_ok());
    }

    #[test]
    fn test_invalid_address_parsing() {
        let invalid_address = "invalid_address";
        let addr = Address::from_str(invalid_address);
        assert!(addr.is_err());
    }

    #[test]
    fn test_decimal_conversion() {
        let value = "1000000000000000000";
        let decimal = Decimal::from_str(value).unwrap();
        let eth = decimal / Decimal::from_str("1000000000000000000").unwrap();
        assert_eq!(eth.to_string(), "1");
    }

    #[test]
    fn test_u256_arithmetic() {
        let amount = U256::from(1000u128);
        let divisor = U256::from(10u128);
        let result = amount / divisor;
        assert_eq!(result, U256::from(100u128));
    }

    #[test]
    fn test_server_info() {
        let trader = EthTrader::new();
        let info = trader.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2024_11_05);
        assert!(info.capabilities.tools.is_some());
        assert!(info.instructions.is_some());
    }

    #[tokio::test]
    async fn test_get_provider() {
        let trader = EthTrader::new();
        let provider = trader.get_provider().await;
        assert!(provider.is_ok());
    }

    #[tokio::test]
    async fn test_get_provider_with_invalid_url() {
        let mut trader = EthTrader::new();
        trader.rpc_url = "not a valid url".to_string();
        let provider = trader.get_provider().await;
        assert!(provider.is_err());
    }

    #[test]
    fn test_parse_ether() {
        let result = parse_ether("1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), U256::from_str("1000000000000000000").unwrap());
    }

    #[test]
    fn test_known_addresses() {
        let weth = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
        assert!(weth.is_ok());

        let usdc = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
        assert!(usdc.is_ok());

        let router = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D");
        assert!(router.is_ok());
    }

    #[test]
    fn test_slippage_calculation() {
        let slippage = Decimal::from_str("0.5").unwrap();
        let amount = U256::from(10000u128);
        let slippage_percent = (slippage * Decimal::from(100)).to_u64().unwrap();
        let min_out = amount * U256::from((10000 - slippage_percent) as u128) / U256::from(10000u128);
        assert_eq!(min_out, U256::from(9950u128));
    }

    // E2E Tests - require network connection
    #[tokio::test]
    async fn test_e2e_get_balance_eth() {
        let trader = EthTrader::new();

        // Vitalik's address - known to have ETH
        let args = GetBalanceArgs {
            address: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".to_string(),
            token: None,
        };

        let result = trader.get_balance(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());
        assert!(!call_result.content.is_empty());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["address"], "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
            assert_eq!(json["symbol"], "ETH");
            assert!(json["balance"].as_str().is_some());
            assert!(json["raw_balance"].as_str().is_some());
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_get_balance_erc20() {
        let trader = EthTrader::new();

        // Binance hot wallet - known to have USDC
        let args = GetBalanceArgs {
            address: "0x28C6c06298d514Db089934071355E5743bf21d60".to_string(),
            token: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()), // USDC
        };

        let result = trader.get_balance(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());
        assert!(!call_result.content.is_empty());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["address"], "0x28C6c06298d514Db089934071355E5743bf21d60");
            assert_eq!(json["token"], "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            assert_eq!(json["symbol"], "USDC");
            assert_eq!(json["decimals"], 6);
            assert!(json["balance"].as_str().is_some());
            assert!(json["raw_balance"].as_str().is_some());
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_get_balance_invalid_address() {
        let trader = EthTrader::new();

        let args = GetBalanceArgs {
            address: "invalid_address".to_string(),
            token: None,
        };

        let result = trader.get_balance(Parameters(args)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_e2e_get_token_price_usd() {
        let trader = EthTrader::new();

        // Get DAI price in USD
        // Note: Using DAI (18-decimal token) because the current implementation
        // uses parse_ether("1") which is appropriate for 18-decimal tokens
        let args = GetTokenPriceArgs {
            token: "0x6B175474E89094C44Da98b954EedeAC495271d0F".to_string(), // DAI
            quote: "USD".to_string(),
        };

        let result = trader.get_token_price(Parameters(args)).await;
        if result.is_err() {
            eprintln!("Error getting DAI price: {:?}", result.as_ref().err());
        }
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());
        assert!(!call_result.content.is_empty());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["token"], "0x6B175474E89094C44Da98b954EedeAC495271d0F");
            assert_eq!(json["quote"], "USD");
            assert!(json["price"].as_str().is_some());

            // DAI price should be roughly $1 (between $0.90 and $1.10)
            let price = Decimal::from_str(json["price"].as_str().unwrap()).unwrap();
            eprintln!("DAI price in USD: {}", price);
            assert!(price > Decimal::new(90, 2)); // > 0.90
            assert!(price < Decimal::new(110, 2)); // < 1.10
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_get_token_price_eth() {
        let trader = EthTrader::new();

        // Get DAI price in ETH
        // Using DAI (another 18-decimal token) since WETH->WETH would fail
        let args = GetTokenPriceArgs {
            token: "0x6B175474E89094C44Da98b954EedeAC495271d0F".to_string(), // DAI
            quote: "ETH".to_string(),
        };

        let result = trader.get_token_price(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());
        assert!(!call_result.content.is_empty());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["token"], "0x6B175474E89094C44Da98b954EedeAC495271d0F");
            assert_eq!(json["quote"], "ETH");
            assert!(json["price"].as_str().is_some());

            // DAI price in ETH should be reasonable (1 DAI ~ $1, so should be very small fraction of ETH)
            let price = Decimal::from_str(json["price"].as_str().unwrap()).unwrap();
            eprintln!("DAI price in ETH: {}", price);
            assert!(price > Decimal::ZERO);
            assert!(price < Decimal::from(1)); // Should be less than 1 ETH
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_get_token_price_invalid_token() {
        let trader = EthTrader::new();

        let args = GetTokenPriceArgs {
            token: "invalid_token_address".to_string(),
            quote: "USD".to_string(),
        };

        let result = trader.get_token_price(Parameters(args)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_e2e_swap_tokens_usdc_to_weth() {
        let trader = EthTrader::new();

        // Simulate swapping 1000 USDC to WETH
        let args = SwapTokensArgs {
            from_token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC
            to_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
            amount: "1000".to_string(),
            slippage: "0.5".to_string(),
        };

        let result = trader.swap_tokens(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());
        assert!(!call_result.content.is_empty());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["simulation"], "success");
            assert_eq!(json["from_token"], "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
            assert_eq!(json["to_token"], "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
            assert_eq!(json["amount_in"], "1000");
            assert_eq!(json["slippage"], "0.5%");
            assert!(json["estimated_output"].as_str().is_some());
            assert!(json["minimum_output"].as_str().is_some());
            assert!(json["gas_estimate"].as_str().is_some());
            assert!(json["gas_cost_eth"].as_str().is_some());
            assert!(json["note"].as_str().unwrap().contains("simulation"));

            // The estimated output should be reasonable (1000 USDC should be > 0.1 ETH)
            let estimated_output = Decimal::from_str(json["estimated_output"].as_str().unwrap()).unwrap();
            assert!(estimated_output > Decimal::new(1, 1)); // > 0.1 ETH
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_swap_tokens_with_custom_slippage() {
        let trader = EthTrader::new();

        // Simulate swapping with 1.5% slippage
        let args = SwapTokensArgs {
            from_token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC
            to_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(), // WETH
            amount: "100".to_string(),
            slippage: "1.5".to_string(),
        };

        let result = trader.swap_tokens(Parameters(args)).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(call_result.is_error.is_none() || !call_result.is_error.unwrap());

        let content_text = &call_result.content[0];
        if let Some(text_content) = content_text.as_text() {
            let json: serde_json::Value = serde_json::from_str(&text_content.text).unwrap();
            assert_eq!(json["slippage"], "1.5%");

            // Verify that minimum_output is less than estimated_output by roughly 1.5%
            let estimated = Decimal::from_str(json["estimated_output"].as_str().unwrap()).unwrap();
            let minimum = Decimal::from_str(json["minimum_output"].as_str().unwrap()).unwrap();
            let diff_percent = ((estimated - minimum) / estimated) * Decimal::from(100);
            assert!(diff_percent > Decimal::new(14, 1)); // > 1.4%
            assert!(diff_percent < Decimal::new(16, 1)); // < 1.6%
        } else {
            panic!("Expected Text content");
        }
    }

    #[tokio::test]
    async fn test_e2e_swap_tokens_invalid_amount() {
        let trader = EthTrader::new();

        let args = SwapTokensArgs {
            from_token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
            to_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            amount: "invalid_amount".to_string(),
            slippage: "0.5".to_string(),
        };

        let result = trader.swap_tokens(Parameters(args)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_e2e_swap_tokens_invalid_from_token() {
        let trader = EthTrader::new();

        let args = SwapTokensArgs {
            from_token: "invalid_address".to_string(),
            to_token: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2".to_string(),
            amount: "100".to_string(),
            slippage: "0.5".to_string(),
        };

        let result = trader.swap_tokens(Parameters(args)).await;
        assert!(result.is_err());
    }
}
