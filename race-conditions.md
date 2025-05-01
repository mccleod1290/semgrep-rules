# Building Effective Semgrep Rules for Race Condition Detection

## Introduction

Race conditions are notoriously difficult to detect through standard code reviews, making automated tools like Semgrep invaluable for identifying these subtle vulnerabilities. In this post, I'll walk through the process of building an effective Semgrep rule to detect race conditions like the one found in the HTB Diogenes' Rage challenge.

We'll focus on:
- Analyzing the vulnerable code pattern
- Creating a basic Semgrep rule
- Refining the rule to reduce false positives
- Testing and validating our approach

## Understanding the Vulnerable Pattern

Before writing a Semgrep rule, we need to understand the exact code pattern that creates the race condition. Looking at the vulnerable endpoint in Diogenes' Rage:

```javascript
router.post('/api/coupons/apply', AuthMiddleware, async (req, res) => {
    try {
        // Get user from database
        const user = await db.getUser(req.data.username);
        
        // Check if coupon exists in redeemed coupons
        if (user.coupons.includes(req.body.coupon_code)) {
            return res.send('Coupon already redeemed!');
        }
        
        // Get coupon value from database
        const value = await db.getCouponValue(req.body.coupon_code);
        
        // Add the coupon to user's redeemed coupons
        await db.setCoupon(user.username, req.body.coupon_code);
        
        // Add the value to user's balance
        await db.addBalance(user.username, value);
        
        return res.send('Coupon redeemed successfully!');
    } catch(e) {
        console.log(e);
        return res.status(500).send('Internal server error');
    }
});
```

The key pattern is:
1. Retrieve data from database
2. Check a condition based on retrieved data
3. Perform multiple database operations based on the condition check
4. No transaction mechanism to ensure atomicity

## Step 1: Basic Pattern Matching

Let's start with a basic Semgrep pattern that looks for this sequence:

```yaml
rules:
  - id: race-condition-coupon-redemption
    pattern: |
      const $USER = await $DB.getUser($USERNAME);
      ...
      if (!$USER.$COUPON_LIST.includes($COUPON_CODE)) {
        ...
        await $DB.setCoupon($USER.$ID_FIELD, $COUPON_CODE);
        ...
      }
    message: |
      Potential race condition detected: check-then-act pattern without
      proper synchronization may lead to concurrent access issues.
    languages: [javascript]
    severity: WARNING
```

This basic pattern looks for the key elements: retrieving user data, checking a condition, and then performing an update operation.

## Step 2: Handling Code Variations

However, this basic pattern is too rigid. Real-world code may use different variable names, different function call patterns, or even different database access methods. Let's make our rule more flexible:

```yaml
rules:
  - id: race-condition-coupon-redemption
    patterns:
      - pattern-inside: |
          async $FUNC($REQ, $RES) {
            ...
            const $USER = await $DB.getUser($USERNAME);
            ...
            if (!$USER.$FIELD.includes($CODE)) {
              ...
            }
            ...
          }
      - pattern: |
          await $DB.$METHOD($USER.$ID, $VALUE);
    message: |
      Potential race condition detected: Database record is checked then
      modified without a transaction or locking mechanism.
    languages: [javascript]
    severity: WARNING
```

This approach uses `pattern-inside` to establish the context and a separate `pattern` to find database operations within that context.

## Step 3: Focusing on Promise Chains

The vulnerable code in Diogenes' Rage uses async/await, but some codebases might use promise chains instead. Let's add support for that pattern:

```yaml
rules:
  - id: race-condition-promise-chain
    patterns:
      - pattern-inside: |
          $DB.getUser($USERNAME).then($USER => {
            ...
            if (!$USER.$FIELD.includes($CODE)) {
              ...
              $DB.$METHOD($USER.$ID, $CODE);
              ...
            }
            ...
          })
    message: |
      Potential race condition in promise chain: Database record is checked
      then modified without proper synchronization.
    languages: [javascript]
    severity: WARNING
```

## Step 4: Excluding Safe Patterns

To reduce false positives, we should exclude patterns that are likely to be safe implementations:

```yaml
rules:
  - id: race-condition-nosync
    patterns:
      - pattern-inside: |
          $DB.getUser($USERNAME).then($USER => {
            ...
            if (!$USER.$FIELD.includes($CODE)) {
              ...
            }
            ...
          })
      - pattern: $DB.$METHOD($USER.$ID, $VALUE);
      - pattern-not: $DB.beginTransaction();
      - pattern-not: $DB.transaction(async $CONN => { ... });
      - pattern-not: $LOCK.acquire();
    message: |
      Race condition risk: Database record check and update operations are not
      wrapped in a transaction or protected by a lock.
    languages: [javascript]
    severity: ERROR
```

This rule now excludes code that uses transactions or locking mechanisms, which are common ways to prevent race conditions.

## Step 5: Adding Metavariable Constraints

To make our rule even more precise, we can add constraints on the metavariables:

```yaml
rules:
  - id: race-condition-coupon-toctou
    patterns:
      - pattern-inside: |
          $DB.getUser($USERNAME).then($USER => {
            ...
            if (!$USER.$COUPON_FIELD.includes($COUPON_CODE)) {
              ...
              $DB.setCoupon($USER.$ID_FIELD, $COUPON_CODE);
            }
          })
      - pattern-not: $DB.beginTransaction()
      - metavariable-regex:
          metavariable: $COUPON_FIELD
          regex: (coupons|redeemedCoupons|usedCoupons|vouchers)
      - metavariable-regex:
          metavariable: $ID_FIELD
          regex: (username|id|userId|user_id)
    message: |
      TOCTOU Race Condition (HTB Diogenes' Rage Style): 
      Coupon redemption lacks atomic check-update. Use transactions/row locks.
    languages: [javascript]
    severity: ERROR
```

By adding metavariable regex constraints, we make the rule more specific to coupon redemption scenarios while still allowing for common naming variations.

## Step 6: Addressing Complex Patterns

Real-world applications might use more complex patterns. Let's improve our rule to handle different coding styles:

```yaml
rules:
  - id: race-condition-toctou-comprehensive
    patterns:
      - pattern-either:
          # Async/await pattern
          - patterns:
              - pattern-inside: |
                  async $FUNC($REQ, $RES) {
                    ...
                    const $USER = await $DB.getUser($USERNAME);
                    ...
                    if (!$USER.$FIELD.includes($CODE)) {
                      ...
                      await $DB.$METHOD($USER.$ID, $CODE);
                      ...
                    }
                    ...
                  }
              - pattern-not: await $DB.transaction(async $CONN => { ... })
          # Promise chain pattern
          - patterns:
              - pattern-inside: |
                  $DB.getUser($USERNAME).then($USER => {
                    ...
                    if (!$USER.$FIELD.includes($CODE)) {
                      ...
                      $DB.$METHOD($USER.$ID, $CODE);
                      ...
                    }
                    ...
                  })
              - pattern-not: $DB.transaction()
    message: |
      Time-of-Check to Time-of-Use (TOCTOU) race condition detected. 
      Multiple database operations should be wrapped in a transaction.
    languages: [javascript]
    severity: ERROR
```

This rule now handles both async/await and promise chain patterns while excluding code that properly uses transactions.

## Step 7: Testing and Validation

Testing Semgrep rules is crucial to ensure they correctly identify vulnerabilities without excessive false positives. Here's how we can test our rule:

1. Create test files with vulnerable and safe code patterns
2. Run Semgrep against these files
3. Refine the rule based on results

Example command for testing:
```bash
semgrep --config race-condition-rule.yaml test-files/
```

## Challenges in Writing Race Condition Detection Rules

Creating effective Semgrep rules for race conditions comes with several challenges:

### 1. Context Sensitivity

Race conditions depend on the broader context of how code is executed. A pattern that's vulnerable in one context might be safe in another, making it difficult to create universal rules.

### 2. Diverse Implementation Patterns

Developers might use different patterns to achieve the same functionality:
- Async/await vs. Promise chains
- Different database libraries with varying APIs
- Custom abstraction layers over database operations

### 3. False Positives

Some code might appear vulnerable based on the pattern but actually be safe due to:
- Application-level locking mechanisms not visible in the immediate code
- Single-threaded execution environments
- Intentional design decisions where race conditions aren't security critical

### 4. False Negatives

Conversely, some vulnerable code might be missed because:
- The race condition spans multiple files
- Custom abstractions hide the actual pattern
- The vulnerability requires understanding of business logic

## Best Practices for Race Condition Rules

1. **Start Specific**: Begin with rules targeting specific, known-vulnerable patterns like the one in Diogenes' Rage
2. **Gradually Generalize**: Expand rules as you confirm their effectiveness
3. **Use Multiple Rules**: Create separate rules for different variations rather than one complex rule
4. **Review Findings Manually**: Always manually review Semgrep findings to confirm vulnerabilities
5. **Combine with Testing**: Supplement static analysis with dynamic testing for race conditions

## Final Refined Rule

Here's our final, refined rule that balances specificity with flexibility:

```yaml
rules:
  - id: htb-diogenes-race-condition
    patterns:
      # Core vulnerability pattern
      - pattern-inside: |
          $DB.getUser($USER).then($USER_OBJ => {
            ...
            if (!$USER_OBJ.$COUPON_FIELD.includes($COUPON_CODE)) {
              ...
              $DB.setCoupon($USER_OBJ.$USER_ID_FIELD, $COUPON_CODE);
            }
          })
      # Ancillary checks
      - pattern-not: $DB.beginTransaction()  # No transaction = vulnerable
      - metavariable-regex:
          metavariable: $COUPON_FIELD
          regex: (coupons|redeemedCoupons)
      - metavariable-regex:
          metavariable: $COUPON_CODE
          regex: (coupon_code|voucher_code)
      - metavariable-regex:
          metavariable: $USER_ID_FIELD
          regex: (username|user_id|id)
    message: |
      TOCTOU Race Condition (HTB Diogenes' Rage Style): 
      Coupon redemption lacks atomic check-update. Use transactions/row locks.
    languages: [javascript]
    severity: ERROR
```

## Conclusion

Creating effective Semgrep rules for race conditions requires a deep understanding of both the vulnerability pattern and the limitations of static analysis. By focusing on specific, high-risk patterns like the coupon redemption vulnerability in Diogenes' Rage, we can develop rules that help identify similar issues across codebases.

Remember that Semgrep is just one tool in your security arsenal. While it can help identify potential race conditions, comprehensive security testing should also include code reviews, dynamic analysis, and penetration testing.

By building a library of targeted rules for common race condition patterns, you can significantly improve your ability to detect these subtle but potentially critical vulnerabilities before they make it into production.

---

*This blog post is based on the race condition vulnerability in the HTB Diogenes' Rage challenge. The Semgrep rules and code patterns are provided for educational purposes to improve security practices.*
