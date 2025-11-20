# Ethereum Trading MCP Server

A Model Context Protocol (MCP) server built in Rust that enables AI agents to query balances and execute token swaps on Ethereum.

## Features

- **get_balance** - Query ETH and ERC20 token balances for any address
- **get_token_price** - Get real-time token prices in USD or ETH via Uniswap
- **swap_tokens** - Simulate Uniswap V2 token swaps with gas estimation (simulation only, not executed on-chain)

## Technical Stack

- **Rust** with async runtime (tokio)
- **Alloy** - Ethereum library for Rust
- **RMCP** - Model Context Protocol SDK for Rust
- **Uniswap V2** - DEX integration for price quotes and swap simulation
- **rust_decimal** - High-precision decimal arithmetic for financial calculations

## Setup

### Prerequisites

- Rust 1.70+ (`cargo --version`)
- Ethereum RPC endpoint (Infura, Alchemy, or public endpoint)

### Installation

1. Clone the repository:

```bash
git clone https://github.com/uu-z/rust-eth-mcp
cd rust-eth-mcp
```

2. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your RPC URL (optional, defaults to public endpoint)
```

3. Build the project:

```bash
cargo build --release
```

4. Run the server:

```bash
cargo run --release
```

The server will start on `http://127.0.0.1:8000/mcp`

## Environment Variables

- `ETH_RPC_URL` - Ethereum RPC endpoint (default: https://eth.llamarpc.com)
- `PRIVATE_KEY` - Private key for transaction signing (optional, for future on-chain execution)
- `RUST_LOG` - Log level (default: info)

## Usage Examples

### MCP Tool Calls

#### 1. Get ETH Balance

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_balance",
    "arguments": {
      "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"address\":\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\",\"balance\":\"1.234567890123456789\",\"symbol\":\"ETH\",\"raw_balance\":\"1234567890123456789\"}"
      }
    ],
    "isError": false
  }
}
```

#### 2. Get ERC20 Token Balance

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_balance",
    "arguments": {
      "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"address\":\"0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045\",\"token\":\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\",\"symbol\":\"USDC\",\"balance\":\"1000.500000\",\"decimals\":6,\"raw_balance\":\"1000500000\"}"
      }
    ],
    "isError": false
  }
}
```

#### 3. Get Token Price

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "get_token_price",
    "arguments": {
      "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "quote": "ETH"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"token\":\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\",\"quote\":\"ETH\",\"price\":\"0.000285\",\"path\":[\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\",\"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\"]}"
      }
    ],
    "isError": false
  }
}
```

#### 4. Simulate Token Swap

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "swap_tokens",
    "arguments": {
      "from_token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "to_token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "amount": "1000",
      "slippage": "0.5"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"simulation\":\"success\",\"from_token\":\"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48\",\"to_token\":\"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\",\"amount_in\":\"1000\",\"estimated_output\":\"0.285\",\"minimum_output\":\"0.283575\",\"slippage\":\"0.5%\",\"gas_estimate\":\"150000\",\"gas_cost_eth\":\"0.0045\",\"note\":\"This is a simulation only. Transaction not executed on-chain.\"}"
      }
    ],
    "isError": false
  }
}
```

## Design Decisions

1. **Alloy Framework**: Chosen for its modern, type-safe approach to Ethereum interactions with excellent async support and compile-time ABI verification using the `sol!` macro.

2. **Simulation-Only Swaps**: The `swap_tokens` tool constructs real Uniswap V2 transactions and queries on-chain data via `getAmountsOut`, but executes them as simulations using RPC `eth_call` semantics (via alloy's view function calls). This provides accurate estimates without on-chain execution.

3. **Decimal Precision**: Uses `rust_decimal` for all balance and price calculations to avoid floating-point precision errors common in financial applications.

4. **Modular Architecture**: Ethereum trading logic is isolated in the `ethereum` module, making it easy to extend with additional DEXs or features while keeping the MCP server logic clean.

5. **Error Handling**: All errors are mapped to MCP-compliant error responses with detailed context for debugging.

## Known Limitations

- **Mainnet Only**: Currently configured for Ethereum mainnet. Testnet support requires updating contract addresses.
- **Uniswap V2 Only**: Price quotes and swaps use Uniswap V2. V3 support could be added for better pricing on certain pairs.
- **No On-Chain Execution**: Swaps are simulated only. Private key management and transaction signing are implemented but execution is intentionally disabled for safety.
- **Public RPC Limits**: Default public RPC endpoint may have rate limits. Use Infura/Alchemy for production.
- **Token Whitelist**: Price queries assume tokens have WETH pairs. Exotic tokens may fail.

## Testing

Run tests:

```bash
cargo test
```

Note: Tests require network access to query Ethereum mainnet. Some tests may be slow due to RPC calls.

## Project Structure

```
src/
├── main.rs           # MCP server setup and HTTP endpoint
├── ethereum/
│   └── mod.rs        # Ethereum trading tools (balance, price, swap)
└── common/           # Example counter (can be removed)
```

## License

MIT

## Contributing

Pull requests welcome. Please ensure:

- Code compiles with `cargo build`
- Tests pass with `cargo test`
- New features include documentation
