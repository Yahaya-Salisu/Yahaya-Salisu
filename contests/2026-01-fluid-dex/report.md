> Valid Low Severity Findings (Acknowledged by Judges)

> **Note:** Valid per judge feedback but not rewarded — Sherlock only compensates High and Medium severity issues.

# Precision Loss in Token Amount Conversions

### Summary
The protocol performs multiple conversions between normal amounts and raw adjusted amounts with different decimal representations. The rounding operations, while favoring the protocol, can accumulate precision losses especially for tokens with non-standard decimals (particularly those remapped from 18 to 15 decimals). This is especially problematic in the withdraw function where multiple rounding operations compound the precision loss.
```solidity
// In withdraw function:  
v_.amount0 = (v_.amount0RawAdjusted * c_.token0DenominatorPrecision * c_.token0SupplyExchangePrice * ROUNDING_FACTOR_MINUS_ONE) /  
    (c_.token0NumeratorPrecision * LC.EXCHANGE_PRICES_PRECISION * ROUNDING_FACTOR);  
if (v_.amount0 > 0) {  
    v_.amount0 -= 1; // Just subtracting 1 so protocol remains on the winning side  
}  
  
v_.amount1 = (v_.amount1RawAdjusted * c_.token1DenominatorPrecision * c_.token1SupplyExchangePrice * ROUNDING_FACTOR_MINUS_ONE) /   
    (c_.token1NumeratorPrecision * LC.EXCHANGE_PRICES_PRECISION * ROUNDING_FACTOR);  
if (v_.amount1 > 0) {  
    v_.amount1 -= 1; // Just subtracting 1 so protocol remains on the winning side  
}  
```

### Root Cause
In contracts/protocols/dexV2/dexTypes/d3/core/userModule.sol#L230-L240

https://github.com/sherlock-audit/2026-01-fluid-dex-v2/blob/main/fluid-contracts%2Fcontracts%2Fprotocols%2FdexV2%2FdexTypes%2Fd3%2Fcore%2FuserModule.sol#L230-L240

### Internal Pre-conditions
Protocol performs decimal conversion, required by design for tokens remapped from 18 to 15 decimals
Multiple rounding operations applied - Happens in every withdrawal as shown in the code

### External Pre-conditions
User tries to withdraw liquidity
Token has non-18 decimals which is common for USDC (6), WBTC (8), or protocol-remapped tokens.

### Attack Path
Example with 18 decimal token (mapped to 15 internally)

User deposits 0.001 tokens (1e15 in 18 decimals)
After conversion to 15 decimals: 1e12
After raw adjustment with exchange price 1.1e18: ~909090909
After liquidity calculations and rounding: ~909090000
Converting back with multiple rounding steps:
Result could be 0.000999 tokens (0.1% loss)
With additional -1 subtractions: 0.000998 tokens
Total loss: 0.2% on small amounts

### Impact
Users could lose significant amounts due to precision loss, especially when withdrawing small amounts or when dealing with tokens that have extreme exchange rates. This could make certain positions uneconomical to close.

### PoC
No response

### Mitigation
// Use a single rounding operation at the end  
```solidity
function withdraw(...) {  
    // Perform all calculations in highest precision  
    uint256 amount0Precise = (v_.amount0RawAdjusted * c_.token0DenominatorPrecision * c_.token0SupplyExchangePrice) /  
        (c_.token0NumeratorPrecision * LC.EXCHANGE_PRICES_PRECISION);  
      
    // Apply rounding only once at the final step  
    if (amount0Precise > 0) {  
        // Round down by a smaller amount for better precision  
        v_.amount0 = (amount0Precise * 999999) / 1000000; // 0.0001% rounding instead of multiple steps  
    }  
      
    // Consider implementing minimum amount thresholds  
    require(v_.amount0 >= minWithdrawAmount, "Amount too small");  
}  
```