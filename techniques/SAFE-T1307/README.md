# SAFE-T1307: Confused Deputy Attack

## Overview
**Tactic**: Privilege Escalation (ATK-TA0004)  
**Technique ID**: SAFE-T1307  
**Severity**: High  
**First Observed**: Not observed in production MCP implementations (theoretical for MCP, but well-documented in OAuth/cloud systems)  
**Last Updated**: 2025-11-08

## Description
A Confused Deputy Attack occurs when an MCP server with legitimate authority is tricked into misusing its privileges by forwarding authentication tokens or credentials from one user (Alice) to another user's (Bob) MCP instance. The server acts as a "confused deputy"—an intermediary with trusted privileges that performs actions on behalf of an attacker without proper authorization checks.

In MCP environments, this attack exploits the trusted position of MCP servers that handle authentication tokens for multiple users or instances. When a server receives a token scoped for one user but fails to validate the intended recipient before forwarding it, an attacker can leverage the server's authority to impersonate the original token owner and access resources or perform actions beyond their privilege level. The [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) explicitly call out Confused Deputy risks for proxy servers and require per-client consent and audience separation to prevent token passthrough and consent bypass.

## Attack Vectors
- **Primary Vector**: Token forwarding between MCP instances without proper audience validation
- **Secondary Vectors**: 
  - Exploitation of shared MCP servers handling multiple user contexts
  - Cross-instance token relay through compromised middleware
  - OAuth token forwarding without audience claim verification
  - Session token reuse across different user contexts in multi-tenant MCP deployments

## Technical Details

### Prerequisites
- Access to an MCP server that handles tokens for multiple users or instances
- MCP server that forwards authentication credentials without proper validation
- Lack of audience or recipient validation in token handling logic
- Ability to intercept or influence token routing decisions

### Attack Flow

```mermaid
graph TD
    A[Alice: Legitimate User] -->|1. Authenticates| B[Authorization Server]
    B -->|2. Issues Token for Alice| C[MCP Server]
    
    D[Bob: Attacker] -->|3. Manipulates Request| C
    
    C -->|4. Forwards Alice's Token| E{Victim Check}
    E -->|No Validation| F[Bob's MCP Instance]
    E -->|With Validation| G[Request Rejected]
    
    F -->|5. Uses Alice's Token| H[Protected Resources]
    H -->|6. Grants Access| I[Alice's Data Exposed]
    
    style D fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style C fill:#fee090,stroke:#000,stroke-width:2px,color:#000
    style F fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style I fill:#d73027,stroke:#000,stroke-width:2px,color:#fff
    style G fill:#91bfdb,stroke:#000,stroke-width:2px,color:#000
```

1. **Initial Stage**: Alice authenticates to an authorization server and receives a token
2. **Token Reception**: MCP server receives Alice's token for processing
3. **Manipulation Stage**: Attacker Bob manipulates routing or intercepts the token flow
4. **Confused Deputy Action**: MCP server forwards Alice's token to Bob's instance without proper validation
5. **Exploitation Stage**: Bob's MCP instance uses Alice's token to access protected resources
6. **Post-Exploitation**: Bob successfully accesses Alice's data or performs actions as Alice

### Example Scenario

**Configuration with Vulnerability:**
```json
{
  "mcp_server": {
    "name": "shared-oauth-proxy",
    "token_handling": {
      "validate_audience": false,
      "validate_recipient": false,
      "forward_tokens": true
    },
    "clients": [
      {
        "user_id": "alice",
        "instance_id": "alice-mcp-instance"
      },
      {
        "user_id": "bob", 
        "instance_id": "bob-mcp-instance"
      }
    ]
  }
}
```

**Attack Request:**
```http
POST /mcp/forward-request HTTP/1.1
Host: shared-mcp-server.example.com
Authorization: Bearer eyJhbGc...AliceToken
X-Forward-To: bob-mcp-instance
Content-Type: application/json

{
  "method": "resources/read",
  "params": {
    "uri": "file:///alice/secrets.json"
  }
}
```

**Result**: The MCP server forwards Alice's token to Bob's instance, allowing Bob to read Alice's files.

### Advanced Attack Techniques

#### Multi-Hop Token Relay (well-studied in OAuth/OpenID Connect)

According to formal security analyses and real-world deployments, attackers can chain multiple confused deputy vulnerabilities:

1. **IdP Mix-Up / Confused Deputy in OAuth & OIDC**: Formal analyses show clients can be tricked into using an authorization code from one IdP with another IdP's token endpoint, enabling token theft or login confusion. These "mix-up"/"malicious endpoint" attacks were found viable against deployed RPs, prompting IETF mix-up mitigations (binding responses to the expected issuer) and updates to best practices ([A Comprehensive Formal Security Analysis of OAuth 2.0 - Fett, Küsters, Schmitz](https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf))

2. **Cross-Service Token Pivoting**: Misconfigured trust (e.g., OIDC WebIdentity trust for CI/CD) lets a deputy accept tokens from unintended principals; real-world hunts have shown misconfigured AWS IAM roles assumable by untrusted GitHub Actions ([Datadog Security Labs - GitHub to AWS Keyless Authentication Flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/))

3. **Token Substitution via Middleware**: Proxy layers that pass through or rewrite tokens without audience checks enable confused-deputy flows (explicitly prohibited by the MCP authorization guidance) ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices))

4. **Context Confusion in Multi-Tenant Systems**: Mixing user contexts on shared deputies (gateways, job runners, build systems) leads to token reuse across tenants; cloud incidents (documented below) illustrate this pattern ([Tenable - ConfusedFunction GCP Vulnerability](https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions))

#### MCP-Specific Attack Variations

##### Cross-Instance Identity Confusion
In MCP environments with multiple connected instances:
- **Shared Server Exploitation**: A centralized MCP server handles requests for many user instances but doesn't enforce per-client consent before third-party OAuth flows; consent cookies for a static client can be abused to skip consent and deliver codes to attacker-controlled redirects ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices))
- **Token Passthrough Anti-Pattern**: Server forwards upstream tokens not issued for the MCP server; forbidden in spec due to control-bypass and audit issues ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices))
- **Tool Chain Abuse**: Attacker manipulates tool invocation chains to cause token forwarding between instances
- **Session Hijacking via Deputy**: Using the MCP server's trusted position to hijack active sessions

##### OAuth Audience Claim Bypass
Modern OAuth implementations use audience claims to prevent confused deputy attacks, but vulnerabilities emerge when:
- **Missing `aud` Validation**: Servers must reject JWTs whose `aud` does not identify the server; this is a core RFC 7519 requirement ([RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519))
- **Wildcard/Broad Audience**: Accepting overly broad audiences or failing to enforce issuer/`aud` pairing invites confused-deputy acceptance ([OAuth 2.0 Mix-Up Mitigation](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-mix-up-mitigation-00))
- **Lack of Proof-of-Possession**: Without mTLS-bound or DPoP-bound tokens, stolen/forwarded bearer tokens can be replayed by the wrong recipient ([RFC 8705 - OAuth 2.0 Mutual-TLS](https://datatracker.ietf.org/doc/html/rfc8705))

## Impact Assessment
- **Confidentiality**: High - Unauthorized access to another user's data and resources
- **Integrity**: High - Ability to perform actions as another user, potentially modifying their data
- **Availability**: Medium - Could enable denial of service by consuming another user's quotas or resources
- **Scope**: Network-wide - Affects all users connected to the vulnerable MCP server

### Current Status (2025)
The Confused Deputy problem dates to Norm Hardy (1988) and remains current in identity/federation and cloud services. Modern mitigations include audience validation, issuer binding, and sender-constrained tokens (mTLS/DPoP):
- OAuth 2.0 includes audience claims (`aud`) to prevent token misuse across different services ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519))
- Token binding mechanisms like mTLS and DPoP provide cryptographic proof of possession ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705), [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html))
- Modern authorization frameworks recommend explicit recipient validation ([OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics))
- MCP's spec adds per-client consent and bans token passthrough ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices))

However, MCP implementations may not enforce these controls, particularly in rapid prototyping or development environments where security configurations are relaxed.

## Detection Methods

### Indicators of Compromise (IoCs)
- Token forwarding events where source and destination user contexts differ
- Authorization headers present in inter-instance communication logs
- Token validation failures with mismatched audience claims
- Unusual cross-instance resource access patterns
- Multiple instances using tokens with identical JTI (JWT ID) values
- Token usage outside expected geographic or network boundaries

### Detection Rules

**Important**: The following rule is written in Sigma format and contains example patterns only. Adapt it to your MCP architecture and logging. Enable comprehensive logging around token handling and instance identity.

```yaml
# EXAMPLE SIGMA RULE - Not comprehensive
title: MCP Confused Deputy Token Forwarding Detection
id: 124759fd-0346-4c13-96bd-92a3aff237e8
status: experimental
description: Detects potential confused deputy attacks where tokens are forwarded between different user instances in MCP environments
author: Arjun Subedi
date: 2025-11-08
references:
  - https://github.com/safe-mcp/techniques/SAFE-T1307
  - https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
  - https://datatracker.ietf.org/doc/html/rfc7519
logsource:
  product: mcp
  service: authentication
detection:
  selection_token_forward:
    event_type: 'token_forward'
    action: 'forward_authorization'
  selection_mismatch:
    - source_user: '*'
      destination_user: '*'
      match_users: false
    - token_audience: '*'
      destination_instance: '*'
      match_audience: false
  selection_cross_instance:
    event_type: 'resource_access'
    original_token_owner: '*'
    accessing_instance_owner: '*'
    owners_match: false
  condition: selection_token_forward and (selection_mismatch or selection_cross_instance)
falsepositives:
  - Legitimate delegation scenarios with explicit user consent
  - Service accounts operating on behalf of multiple users
  - Administrative operations with proper authorization
  - Shared resource access in collaborative environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134  # Access Token Manipulation
  - attack.t1550  # Use Alternate Authentication Material
  - safe.t1307
```

### Behavioral Indicators
- User accounts showing activity from multiple MCP instances simultaneously
- Resource access patterns inconsistent with user's normal behavior
- Token usage with mismatched issuer/audience context
- Sudden spike in cross-instance API calls
- Authorization logs showing tokens used by unintended recipients
- Sessions persisting unusually long when short-lived tokens are expected
- Token usage from unexpected issuer or network/geolocation

## Mitigation Strategies

### Preventive Controls

1. **Strict Audience Validation**: Enforce RFC 7519—only accept JWTs whose `aud` includes this server; reject missing/over-broad audiences
   - Verify `aud` claim matches the intended MCP instance identifier
   - Reject tokens with missing or overly broad audience claims
   - According to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519), audience validation is a core requirement for preventing confused deputy attacks

2. **Sender-Constrained Tokens**: Bind tokens to the client using OAuth mTLS (RFC 8705) or DPoP (RFC 9449) to prevent replay/forwarding
   - Implement mTLS token binding ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705))
   - Deploy DPoP (Demonstrating Proof-of-Possession) for bearer tokens ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html))
   - Ensure tokens cannot be replayed by different instances

3. **Instance Identity Verification**: Validate the identity of requesting MCP instances
   - Implement mutual TLS authentication between MCP components
   - Use instance certificates for cryptographic identity proof
   - Maintain allowlists of authorized instance-to-instance communications

4. **Context Isolation**: Enforce strict separation between user contexts
   - Use separate token storage per user instance
   - Implement namespace isolation for multi-tenant deployments
   - Avoid sharing authentication state across user boundaries

5. **Token Scope Restriction**: Implement principle of least privilege for token scopes
   - Issue tokens with minimal required permissions
   - Use short-lived tokens with frequent rotation
   - Implement fine-grained resource-level authorization

6. **Explicit Recipient Declaration**: For token exchange, require audience/`resource` targeting and validate recipient consistency (RFC 8693)
   - Use token exchange flows that declare the target audience ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html))
   - Implement request signing to prevent token forwarding manipulation
   - Validate that token recipient matches request context

7. **MCP-Specific Controls**: Implement per-client consent at the MCP layer; forbid token passthrough; bind consent to the requesting `client_id` and exact `redirect_uri`
   - Follow [MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices) for OAuth integration
   - Enforce per-client consent rather than static consent cookies
   - Never forward tokens not issued for the MCP server itself

### Detective Controls

1. **Token Usage Monitoring**: Implement comprehensive logging and monitoring
   - Log all token issuance, forwarding, and usage events
   - Monitor for tokens used by multiple instances
   - Alert on audience claim mismatches

2. **Anomaly Detection**: Deploy behavioral analysis for token usage patterns
   - Model typical issuer/audience pairs per instance; flag deviations
   - Detect unusual cross-instance communication patterns
   - Monitor for tokens used outside expected network or geographic boundaries (impossible travel)
   - Identify tokens with suspicious usage timing or frequency

3. **Audit Trail Analysis**: Maintain detailed audit trails
   - Maintain lineage of tokens through any forwarding; correlate with user actions
   - Track token lineage through forwarding chains
   - Regular review of cross-instance access patterns

### Response Procedures

1. **Immediate Actions**:
   - Revoke suspected compromised tokens immediately
   - Isolate affected MCP instances from network
   - Lock accounts showing suspicious cross-instance activity
   - Preserve logs for forensic analysis

2. **Investigation Steps**:
   - Enumerate all instances using the token
   - Trace any forwarding chain to identify initial compromise point
   - Review audit logs for unauthorized resource access
   - Determine scope of data exposure or unauthorized actions
   - Confirm whether consent existed for observed token usage

3. **Remediation**:
   - Force password/credential reset for affected accounts
   - Reissue correctly audience-scoped tokens with proper validation
   - Enable mTLS/DPoP token binding mechanisms
   - Enforce recipient validation and MCP per-client consent
   - Harden token-handling code; conduct security review
   - Expand monitoring for similar attack patterns

## Real-World Context

### Historical Background

The Confused Deputy problem was formalized by Norm Hardy (1988) with the compiler/billing-file example—an intermediary with ambient authority is tricked into misusing it ([The Confused Deputy - ACM Digital Library](https://dl.acm.org/doi/10.1145/54289.871709)). Hardy described a scenario where a compiler program with write access to billing files could be tricked into overwriting arbitrary files by manipulating which file it wrote to while performing its legitimate function.

### Modern Manifestations (Documented Cases)

While not yet observed in production MCP deployments, confused deputy attacks are well-documented in related technologies:

#### OAuth/OpenID Connect Mix-Up (IdP Confusion)

Rigorous formal analyses show RP clients can be confused about which IdP issued a code, enabling token theft or login confusion. Mitigations bind responses to the expected issuer and reinforce `state`/`nonce` handling. Empirical studies found exploitable implementations in the wild ([A Comprehensive Formal Security Analysis of OAuth 2.0 - Fett, Küsters, Schmitz, 2016](https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf)).

#### AWS AppSync Cross-Tenant Confused Deputy (2022)

Datadog disclosed a cross-tenant vulnerability where AppSync could be induced to assume IAM roles in other accounts (bypassing cross-account checks via mixed-case JSON), letting attackers access victim resources. AWS remediated quickly and reported no evidence of customer exploitation; the case remains a canonical confused-deputy pattern ([Datadog Security Labs - AppSync Vulnerability](https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/)).

#### GitHub → AWS OIDC Misconfiguration (2023–2025)

Datadog demonstrated that improper trust policies allowed untrusted GitHub Actions to assume AWS IAM roles; their case study included a UK government role with CodeCommit permissions. This is a practical token-recipient confusion/trust misbinding problem; later AWS added guardrails (2025) blocking creation of such vulnerable roles ([Datadog Security Labs - GitHub to AWS Keyless Authentication Flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/)).

#### GCP "ConfusedFunction" (2024)

Tenable documented a privilege-escalation path in GCP where Cloud Functions' deployment pipeline could be abused to exfiltrate Cloud Build service-account tokens and operate with higher privileges—again a deputy (build system) acting with broader authority than the caller. Google mitigated for new deployments; legacy instances required customer action ([Tenable - ConfusedFunction GCP Vulnerability](https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions)).

#### AWS STS External ID (Ongoing)

AWS treats the confused deputy as a first-class risk; the `ExternalId` in `AssumeRole` trust policies exists specifically to prevent a deputy (a third-party integrator) from being tricked into using its authority on behalf of an unintended principal ([AWS IAM Documentation - The Confused Deputy Problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)).

#### Additional Related Patterns

- **CSRF (Cross-Site Request Forgery)**: Web browsers acting as confused deputies by forwarding cookies to unintended sites ([OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html))
- **SSRF (Server-Side Request Forgery)**: Web servers acting as deputies to make requests to internal resources ([OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html))

### Relevance to MCP

The MCP spec's security best practices directly incorporate these lessons: forbid token passthrough, enforce per-client consent and exact `redirect_uri` matching, and require issuer/audience verification to avoid deputy confusion across clients and third-party APIs ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)). The MCP architecture, with its pattern of servers acting as intermediaries between users and resources, creates similar confused deputy risks that require careful attention to token validation and context isolation.

## Sub-Techniques

### SAFE-T1307.001: OAuth Audience Bypass
Exploiting missing or insufficient audience validation in OAuth token flows:
- Tokens accepted without `aud` claim verification ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519))
- Wildcard or overly permissive audience patterns
- Resource servers accepting tokens not intended for them

### SAFE-T1307.002: Cross-Tenant Token Leakage
In multi-tenant MCP deployments, exploiting insufficient tenant isolation:
- Shared caches or misbound trust (e.g., OIDC WebIdentity) allow unexpected principals to receive/assume tokens across tenants
- Tenant identifiers not properly validated
- Token forwarding between different tenant contexts ([Datadog Security Labs - GitHub to AWS Keyless Authentication Flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/))

### SAFE-T1307.003: Tool Chain Identity Confusion
Exploiting MCP tool invocation chains with multiple authentication contexts:
- A tool running under User A's token invokes another tool in User B's context; original auth context is lost; deputy executes with wrong identity
- Nested tool calls losing original authentication context
- Permission inheritance across tool boundaries
- Prevent with MCP per-client consent and no token passthrough ([MCP Security Best Practices](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices))

## Related Techniques
- [SAFE-T1304](../SAFE-T1304/README.md): Credential Relay Chain - Uses stolen credentials rather than confused deputy pattern
- [SAFE-T1306](../SAFE-T1306/README.md): Rogue Authorization Server - Creates malicious tokens rather than misusing legitimate ones
- [SAFE-T1308](../SAFE-T1308/README.md): Token Scope Substitution - Replaces token scopes rather than forwarding to wrong recipient
- [SAFE-T1506](../SAFE-T1506/README.md): Infrastructure Token Theft - Steals tokens from infrastructure rather than exploiting forwarding logic
- [SAFE-T1706](../SAFE-T1706/README.md): OAuth Token Pivot Replay - Broader token replay attack pattern

## References
- [Model Context Protocol Specification](https://modelcontextprotocol.io/specification)
- [MCP Security Best Practices - Confused Deputy, Token Passthrough prohibitions, per-client consent requirements](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [The Confused Deputy (or why capabilities might have been invented) - Hardy, N. (1988), ACM SIGOPS](https://dl.acm.org/doi/10.1145/54289.871709)
- [A Comprehensive Formal Security Analysis of OAuth 2.0 - Fett, Küsters, Schmitz (2016)](https://publ.sec.uni-stuttgart.de/fettkuestersschmitz-ccs-2016.pdf)
- [RFC 7519 - JSON Web Token (JWT) - audience claim requirements](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 6819 - OAuth 2.0 Threat Model and Security Considerations](https://datatracker.ietf.org/doc/html/rfc6819)
- [OAuth 2.0 Security Best Current Practice - IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 Mix-Up Mitigation - IETF Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-mix-up-mitigation-00)
- [RFC 8693 - OAuth 2.0 Token Exchange - audience/resource targeting](https://www.rfc-editor.org/rfc/rfc8693.html)
- [RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
- [RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession (DPoP) - sender-constraining tokens](https://www.rfc-editor.org/rfc/rfc9449.html)
- [Datadog Security Labs (2022) - AWS AppSync cross-tenant confused-deputy disclosure](https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/)
- [Datadog Security Labs (2023-2025) - GitHub→AWS OIDC misconfiguration; UK Government case; AWS guardrails](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/)
- [Tenable (2024) - ConfusedFunction in GCP Cloud Functions/Cloud Build - privilege escalation](https://www.tenable.com/blog/confusedfunction-a-privilege-escalation-vulnerability-impacting-gcp-cloud-functions)
- [AWS IAM Documentation - External ID to prevent confused deputy in STS AssumeRole](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

## MITRE ATT&CK Mapping
- [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
- [T1550 - Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)
- [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)

## Version History
| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2025-11-08 | Initial documentation of confused deputy attack pattern in MCP context with comprehensive OAuth security references, real-world cases (AWS AppSync, GitHub→AWS OIDC, GCP ConfusedFunction), and MCP-specific mitigations | Arjun Subedi |

