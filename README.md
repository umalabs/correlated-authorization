<!-- @import "style.less" -->

# Correlated Authorization—Draft

<p class="author">
    Igor Zboran<br>
    izboran@gmail.com
</p>
<br>
<p class="abstract">
&emsp;<strong><em>Abstract</em></strong>—<em>Correlated&nbsp;authorization</em> is a dual-authority authorization protocol built on top of User-Managed Access (UMA) [1, 2] and OAuth 2.0 Token Exchange [3] protocols that allows users (resource owners) to delegate access to other users (requesting parties) across security domain boundaries. The requesting party is responsible for creating the request, while the resource owner approves this request either when it is online or by creating a policy. The resource owner and the requesting party may belong to different security domains administered by the respective authorities.</p>
<p class="abstract">
&emsp;This concept uses a permission ticket issued by the resource owner's authorization server as a correlation handle that binds the requesting party's claims to the authorization process. An email address is used as the unique requesting party identifier for cross-domain access control. The challenge-response authentication protocol is used to authenticate the requesting party to the resource owner's authorization server. Trust between the resource owner's authorization server and the requesting party's authorization server is elevated by the push-pull mechanism.
</p>

## I. Introduction

&emsp;With the growing popularity of protocols based on the OAuth 2.0 [4] specification, there is a need for an interoperable standard that specifies how to convey information about the user from an identity provider to an authorization server, especially across security domain boundaries. The problem is that such a system is difficult to design because OAuth2 [4], OIDC [5] and UMA are single-authority protocols. This draft profiles and combines the OAuth2 and UMA protocols into a dual-authority protocol, which not only meets the needs of interoperability, but also elevates trust between mutually unknown parties.

## II. Motivation

&emsp;<em>Correlated&nbsp;authorization</em> is an attempt to revive UMA WG's original idea—UMA wide ecosystem [6], when the resource owner and requesting party might "know each other" in the real world, but the resource owner's authorization server has no pre-established trust with the requesting party or any of their identity/claims providers—in other words, when the resource owner's authorization server and requesting party's identity provider don't know each other.

## III. UMA Wide Ecosystem Concept

&emsp;This high-level view illustrated in Figure&nbsp;1 gives you an idea of relationships between UMA wide ecosystem entities.

UMA uses a special jargon. For the sake of brevity of this paper, the following list of acronyms will be used:

* IdP - Identity Provider
* AS - Authorization Server
* RS - Resource Server
* RO - Resource Owner
* RqP - Requesting Party
* RPT - Requesting Party Token

![UMA Wide Ecosystem](./images/uma-wide-ecosystem.svg)

<p class="figure">
Fig.&nbsp;1.&emsp;Relationships between UMA wide ecosystem entities
</p>

The UMA wide ecosystem concept uses relationship-driven policies to drive automated dual-authority authorization assessment and token issuance. The relationship-driven policies incorporate user-to-user (U2U) relationships and user-to-resource (U2R) relationships.

## IV. Challenge-Response Authentication Protocol

&emsp;Figure&nbsp;2 shows the unilateral entity authentication protocol [7] adapted for the <em>correlated&nbsp;authorization</em> concept by which the claimant authenticates his identity to the verifier.

![Challenge-Response Authentication](./images/challenge-response-authentication.svg)

<p class="figure">
Fig.&nbsp;2.&emsp;Unilateral entity authentication protocol
</p>

&emsp;Successful completion of steps means that the claimant has authenticated itself to the verifier. The ticket represents the random challenge, and the signed ticket hash represents the response. Ticket hash is used here to ensure that the actual value of the ticket is not disclosed to the authenticator.

## V. Push-Pull Trust Elevation

The link to the shared resource should have a unique random name that is delivered to the requesting party through a trusted channel, e.g. email. After receiving the resource link, the requesting party's authorization server must have the policy set correctly, either by the user or automatically by the agent. Only then can the requesting party can download the resource from the resource server. Such a push-pull mechanism elevates trust between the resource owner's authoritative domain and requesting party's authoritative domain.

## VI. Sequence Diagram

&emsp;The following sequence diagram describes the mechanism of the <em>correlated&nbsp;authorization</em> protocol, which relies on the token exchange extension of OAuth2, where an access token is used to obtain a claims token from the Security Token Service (STS) endpoint.

#### *UMA Profile*

&emsp;The sequence diagram illustrated in Figure&nbsp;3 represents a profile of the UMA protocol and is in full compliance with the UMA 2.0 specification<sub><sup><span class="fn">Unlike the UMA specification, the <em>correlated&nbsp;authorization</em> protocol allows the use of the UMA grant with or without client authentication or identification. Whether or not to allow unauthenticated or unidentified clients are policy decisions that are at the discretion of the authorization server.</span><sup></sub>.
<br>
<br>

![Sequence Diagram – UMA](./images/correlated-authorization.svg)

<p class="figure">
Fig.&nbsp;3.&emsp;<em>Correlated&nbsp;authorization</em> sequence diagram
</p>

Prerequisites:

* The AS-RqP supports the OAuth 2.0 Token Exchange [3] extension of OAuth2.
* The AS-RqP publishes its metadata on a URL /.well-known/oauth-authorization-server (alternatively on /.well-known/openid-configuration).
* The AS-RqP also acts as RqP's Identity Provider.
* The client is registered at the AS-RqP as a public or confidential client and acts as a Relying Party in a RqP's Identity Provider in order to obtain an access token with user claims.
* The client should be registered at the AS-RO as a public or confidential client; in case of immediate access, the client does not have to be registered at the AS-RO.
* The RO has set up the RS and registers his 'RS API' resource at the AS-RO according to the UMA Federated Authorization [2] specification.

Steps:

1. The RqP directs the client to access the 'RS API' resource with no access token.
2. The RS requests a permission ticket. <dl><dt></dt><dd>The AS generates the permission ticket itself (ticket is a random NONCE) and the permission token<sub><sup><span class="fn"> The permission token is not mentioned in the UMA specification. A detailed description of the permission token format is out of scope of this paper.</span><sup></sub>, which is bound to the permission ticket through a permission ticket hash. The permission token contains these claims:&nbsp;{issuer,&nbsp;ts,&nbsp;rs_uri,&nbsp;resource_name_hash,&nbsp;permission_ticket_hash} where  
-&nbsp;issuer is the URI that identifies who issues the permission token  
-&nbsp;ts is the timestamp of when the permission ticket was created  
-&nbsp;rs_uri is the URI that identifies the resource server  
-&nbsp;resource_name_hash</em>&nbsp;=&nbsp;Base64URL-Encode(SHA256(resource_name))  
-&nbsp;permission_ticket_hash</em>&nbsp;=&nbsp;Base64URL-Encode(SHA256(permission_ticket))</dd></dl>
3. The AS returns the permission ticket and the permission token.
4. Without an access token, the RS will return HTTP code 401 (Unauthorized) with the permission ticket and the permission token.
5. The client requests a claims token by presenting the access token with user claims, permission token and resource name (token exchange request). <dl><dt></dt><dd>{grant_type&nbsp;=&nbsp;token-exchange,
&nbsp;resource&nbsp;=&nbsp;"RS API",
&nbsp;scope&nbsp;=&nbsp;permission_token resource_name,
&nbsp;subject_token&nbsp;=&nbsp;access_token_with_user_claims,
&nbsp;subject_token_type&nbsp;=&nbsp;urn:ietf:params:oauth:token-type:access_token,
&nbsp;requested_token_type&nbsp;=&nbsp;urn:ietf:params:oauth:token-type:jwt}<br>
The AS-RqP performs an authorization assessment
-&nbsp;1.&nbsp;verify permission_token
-&nbsp;2.&nbsp;compare resource_name_hash vs. Base64URL-Encode(SHA256(resource_name))
-&nbsp;3.&nbsp;evaluate issuer, ts, rs_uri, resource_name<br>
The AS-RqP generates the claim token, which contains these claims:&nbsp;{user_claims,&nbsp;permission_ticket_hash} where
-&nbsp;user_claims are extracted from access_token_with_user_claims
-&nbsp;permission_ticket_hash is extracted from permission_token</dd></dl>
6. After an authorization assessment, it is positive, the AS-RqP returns the claims token.
7. At the AS-RO the client requests an RPT by presenting the claims token and the permission ticket. <dl><dt></dt><dd>{grant_type = uma-ticket,
&nbsp;pushed_claims = claims_token}<br>
The AS-RO performs an authorization assessment
&nbsp;1.&nbsp;verify permission_ticket
&nbsp;2.&nbsp;extract user_claims from claims_token
&nbsp;3.&nbsp;select email_address claim
&nbsp;4.&nbsp;bootstrap discovery of AS-RqP config url from email address via WebFinger;
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;if this doesn't work, build well-known url using domain part of email_address
&nbsp;5.&nbsp;verify claims_token signature
&nbsp;6.&nbsp;evaluate resource = "RS API"
&nbsp;7.&nbsp;extract permission_ticket_hash scope from claims_token
&nbsp;8.&nbsp;compare permission_ticket_hash vs. Base64URL-Encode(SHA256(permission_ticket))
&nbsp;9.&nbsp;evaluate user_claims</dd></dl>
8. After an authorization assessment, it is positive, the AS-RO returns RPT.
9. With the valid RPT the client tries to access the 'RS API'.
10. The RS validates the RPT, it is valid, the RS allow access the protected 'RS API' resource.

## VII. Authority Boundaries, Interactions and Scenarios

&emsp;The <em>correlated&nbsp;authorization</em> protocol allows us to indirectly (through the client) link identity providers with authorization services governed by different authorities that are not required to share information or collaborate.

&emsp;The following scenarios demonstrate a system of trust between two authorities that allows the conveyance of identity information from identity providers to authorization services across security domain boundaries.

#### *A. Identity Federation Scenario*

&emsp;The scenario illustrated in Figure&nbsp;4 allows you to link a single authorization service to multiple identity providers. The client falls under the governance of the resource owner's respective authority.

![Scenario-1](./images/authority-boundaries-scenario-1.svg)

<p class="figure">
Fig.&nbsp;4.&emsp;Identity federation scenario
</p>

#### *B. Federated Authorization Scenario*

&emsp;The federated authorization scenario illustrated in Figure&nbsp;5 allows you to link a single identity provider to multiple authorization services. The client falls under the governance of the requesting party's respective authority.

![Scenario-2](./images/authority-boundaries-scenario-2.svg)

<p class="figure">
Fig.&nbsp;5.&emsp;Federated authorization scenario
</p>

#### *C. Combined Federation Scenario*

&emsp;As the name suggests, the scenario illustrated in Figure&nbsp;6 allows multiple authorization services to be linked to multiple identity providers. The client falls under the governance of a third-party authority.

![Scenario-3](./images/authority-boundaries-scenario-3.svg)

<p class="figure">
Fig.&nbsp;6.&emsp;Combined federation scenario
</p>

## VIII. Use Cases

&emsp;Healthcare and enterprise cross-domain services e.g., email, file sharing, instant messaging, tele-conferencing. Also, Fintech and Telco services.

## IX. Conclusion and Future Work

1.&nbsp;Consider an authentication protocol, where RS/AS acts as an external authoritative attribute/claims provider.
2.&nbsp;Employ the DPoP to bind RPT to the client.
3.&nbsp;Describe how the resource owner can use the <em>correlated&nbsp;authorization</em> protocol.
4.&nbsp;Consider using the <em>correlated&nbsp;authorization</em> mechanism to transfer digital/virtual assets in the form of transactions.

## Acknowledgment

&emsp;This work has benefited from the valuable discussions with Eve Maler, founder of WG-UMA [8]; and Alec Laws, chair of WG-UMA [8]. Both gave feedback that improved this paper’s content. Last but not least, the UMA Work Group archives [9, 10] serve as a source of comprehensive information on authorization-related topics—many thanks to all involved.

## References

<p class="references">
[1]&nbsp;E. Maler, M. Machulak, J. Richer, and T. Hardjono, “User-Managed Access (UMA) 2.0 Grant for OAuth 2.0 Authorization,” Internet Engineering Task Force (2019), https://datatracker.ietf.org/doc/draftmaler-oauth-umagrant-00.<br>
[2]&nbsp;E. Maler, M. Machulak, J. Richer, and T. Hardjono, “Federated Authorization for User-Managed Access (UMA) 2.0,” Internet Engineering Task Force (2019), https://datatracker.ietf.org/doc/draftmaler-oauth-umagrant-00.<br>
[3]&nbsp;M. Jones, A. Nadalin, B. Campbell, J. Bradley, C. Mortimore, “OAuth 2.0 Token Exchange,” RFC 8693 (2020), https://rfc-editor.org/rfc/rfc8693.txt.<br>
[4]&nbsp;E. D. Hardt, “The OAuth 2.0 Authorization Framework,” IETF RFC 6749 (Informational), 2012, http://tools.ietf.org/html/rfc6749.<br>
[5]&nbsp;OpenID specifications at “OpenID Foundation,” 2022, https://openid.net/developers/specs/.<br>
[6]&nbsp;“UMA telecon 2016-03-31” https://kantarainitiative.org/confluence/display/uma/UMA+telecon+2016-03-31<br>
[7]&nbsp;National Institute of Standards and Technology, “FIPS PUB 196: Entity Authentication Using Public Key Cryptography,” 1997. [Online]. Available: https://csrc.nist.gov/csrc/media/publications/fips/196/archive/1997-02-18/documents/fips196.pdf.<br>
[8]&nbsp;“User-Managed Access” Work Group at “Kantara Initiative” https://kantarainitiative.org/confluence/display/uma/Home.<br>
[9]&nbsp;“The WG-UMA Archives” https://kantarainitiative.org/pipermail/wg-uma/.<br>
[10]&nbsp;“Kantara Initiative User Managed Access WG” https://groups.google.com/g/kantara-initiative-uma-wg.<br>
</p>
