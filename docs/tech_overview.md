# **Wires: Technical Overview**

## **Summary**

Wires is a zero-trust virtual network for authenticated, authorized, and audited communication between humans, autonomous agents, and software services. A Wires *fabric* is rooted in a single human, controlled by a hardware-bound key, and joined by nodes — agents, services, other humans — through a pairing flow that issues cryptographically signed credentials. Nodes communicate over end-to-end encrypted channels built on Iroh gossip topics. Hosted relay infrastructure provides always-on gossip presence and an encrypted message log without the ability to read content. What travels on a channel is left to the participants: Wires provides identity, addressing, encryption, authorization, and replay, but does not specify a top-level RPC convention or message schema. Wires is designed as an open protocol. Reference clients on iOS and Android and a hosted infrastructure component will be released as open source.

## **The fabric**

A fabric is the unit of organization in Wires. It is owned by exactly one human and represents the totality of agents, services, and other humans that the user has authorized to communicate within their personal network. Services join the fabric rather than the user joining each service.

The consequence is data sovereignty in a form that survives changes in the user's choice of agent or platform. A user who switches from one LLM provider to another can grant the new provider access to the same fabric the previous provider had; the user's house, car, utilities, and other connected systems do not need to be reconnected. Lock-in becomes a property of the user's choices about whom to grant access, not a property of any single service's data hoard.

Cross-fabric connectivity — for households, shared resources, organizational use — is explicitly deferred. The initial design treats a household with two adults as two fabrics that may grant access to overlapping services, with cross-fabric primitives to be introduced later as a composition layer over the existing model rather than as a primitive.

## **The fabric root**

The fabric is rooted in a cryptographic identity stored in hardware-backed key storage on the user's device. In the reference iOS client, this means Secure Enclave with biometric authentication required to derive the private key in memory; the private key never leaves the device's secure element in plaintext.

The reference iOS client enables iCloud Keychain sync for the root key by default. This makes the fabric usable across the user's Apple devices and recoverable via Apple ID, at the cost of placing Apple's iCloud Keychain in the trust model. Apple's design is intended such that iCloud Keychain contents are not accessible to Apple itself, but the user's fabric continuity is downstream of their Apple account. A user may opt out of sync; in opt-out mode, the root is bound to a single device with no recovery path, and additional devices must be added as separate Nodes via the standard pairing flow.

A reference Android client is planned and will provide an analogous posture using Android's hardware-backed Keystore.

The protocol is open by design and specifies only the signature primitives a root key must produce, not how it is stored or synced. Third-party clients with alternative trust postures — hardware tokens, air-gapped storage, multi-signature schemes — are explicitly anticipated and supported.

## **Nodes**

A Node is any participant in a fabric. Nodes are identified by their public keys and authenticated by Iroh's identity primitives. Node types form a loose taxonomy describing how a Node presents itself:

* **Human**: an actual person, typically participating via a client that exposes a conversational or UI surface.
* **Agent**: persistent autonomous software that initiates and responds, behaving as a simulacrum of human participation. Examples include a Claude session acting as an assistant, an Operator-style browsing agent, or a long-running personal agent.
* **Service**: software that responds but does not typically initiate, providing persistent data or RPC methods to the fabric. Examples include a utility's billing API, thermostat firmware, or a calendar provider.

The taxonomy is not strict. A Node may declare its primary self-presentation while exposing capabilities that span types. A Service may answer arbitrary RPC and also initiate notifications under specified conditions; an Agent may expose RPC alongside its conversational behavior. Type informs UI and default expectations rather than protocol behavior. Behavioral capabilities are channel-level metadata, layered on top of node identity.

## **Topics and channels**

Wires distinguishes two layers:

* A **topic** is the substrate primitive: an Iroh gossip topic identified by a 32-byte id. Iroh provides addressing, delivery, and identity at this layer. The topic is where ciphertext flows.
* A **channel** is the Wires-level construct built on a topic. A channel adds end-to-end encryption under a per-channel epoch key, a roster of participating Nodes with role metadata, history retention semantics, and a replay protocol. Channels are what users and agents reason about.

The same topic id flows through Iroh's gossip and Wires' replay protocol; the same channel id appears in user-facing CLI, MCP tool surfaces, and UI. When this document says "channel," it always means the Wires-level construct. References to the underlying Iroh gossip topic are explicit.

Two channel forms exist:

* **DM channels** are addressed by a topic identifier derived from the participant public-key set. They exist by virtue of the participants knowing about each other and require no fabric-level registration. The derivation is deterministic, so two Nodes that already share fabric membership can open a DM without an explicit key exchange.
* **Named channels** are addressed by a topic identifier registered to the fabric and are discoverable to authorized Nodes within it.

Channel content is end-to-end encrypted under a group key managed per-channel. Encryption is independent of the gossip transport: a gossip observer who joins a topic without the group key sees ciphertext only. Ordering is meaningful within a channel; ordering across channels is not.

## **Authorization**

Authorization in Wires has two layers: a substrate-level fabric grant and channel-level roster membership. Both must hold for a Node to publish to a channel and have that publish be read by others.

The **fabric grant** is a signed credential issued by the fabric root to each paired Node. It binds the Node's public key to its presence in the fabric and to the broad right to participate in channels. The grant is bound to the Node's identity, not bearer-transferable: a Node cannot redelegate its grant by handing the signed credential to a third party. The grant is what gives a Node standing to be in any channel roster at all; without it, a Node has no identity in the fabric.

**Channel-level authorization** is roster membership. A Node has the ability to read and write a specific channel if and only if it is present in that channel's roster with the appropriate role *and* holds the channel's current epoch key. Roster membership is updated by publishing roster-management messages on the channel itself; the epoch key is delivered when a Node is added.

Two consequences follow:

* **Revocation** at the channel level is a roster update followed by an epoch advance on the channel's group key. The revoked Node has no further means to decrypt subsequent content and no standing in the roster. Revoking a Node's fabric grant evicts it from every channel at once.
* **Delegation is invite, not sublease.** A Node with authority to add members to a channel may do so, but a member cannot independently extend its capability to a third party without being granted that authority. The fabric grant itself is non-transferable.

The pairing flow grants both layers at once. When a user wants to connect a service to their fabric, they sign into the service as they normally would, the service presents a pairing code encoding its Iroh node identifier and a nonce, and the user scans the code into the Wires app. The app initiates an Iroh connection, the service declares the channels and roles it requests, and the user approves or modifies the grant. The resulting envelope carries the fabric grant, signed by the root, and the per-channel material — current epoch keys and initial roster entries for the channels the user agreed to — sealed to the requesting Node.

## **Confidentiality and replay**

Each channel uses an epoch-based group keying scheme. Membership changes advance the epoch and rotate the channel key. Hosted infrastructure stores ciphertext only and has no means to derive any channel key.

History replay is a grantable property rather than an automatic one. When a member is added to a channel, an authorized existing member may elect to deliver historical key material to the new member, enabling that member to decrypt past content stored by the hosted relay. The default behavior for a given channel and the conditions under which historical access is granted are application-level choices; the protocol provides the mechanism, not the policy.

The hosted relay can be queried for replay via a dedicated Iroh ALPN. Members with the appropriate key material decrypt locally.

## **Hosted infrastructure**

The reference hosted infrastructure provides three services:

* **Always-on gossip presence** so channels remain available when user-owned devices are offline.
* **Encrypted log retention** so channel content persists and can be replayed.
* **Replay delivery** via a dedicated Iroh ALPN to authorized members.

The infrastructure participates as a Node from a protocol standpoint and is treated by the threat model as a relay-class participant. It can observe metadata — which topics exist, who participates, message sizes, timing — but it has no plaintext access to channel content under any condition. Operators of the hosted infrastructure cannot read fabric content; a legal or technical compromise of the hosted infrastructure does not yield plaintext.

The hosted infrastructure will be released as open source. Once public, operators other than the project may run it, and users with sufficient operational capability may self-host. Reference deployment is provided to lower the operational barrier for typical users.

## **Message semantics: substrate, not protocol**

Wires deliberately does not specify a top-level RPC convention, a capability discovery mechanism, or a schema for inter-agent communication. The substrate provides identity, addressing, encryption, authorization, persistence, and replay; what travels on top is left to the participants.

This is a position rather than an omission. In a context where at least one party to most exchanges has language understanding, fixed protocols give up more than they gain. Two agents can negotiate communication patterns at runtime — discovering each other's capabilities through conversation rather than through a registry, agreeing on a payload schema for a specific exchange, or falling back to natural language when no structured format suffices. The substrate should not prematurely constrain what those negotiations can produce.

Multiple communication patterns are expected to coexist on the same substrate:

* **Conventional RPC** where two parties share a known schema. The MCP gateway is an instance of this pattern.
* **Conversational negotiation** where an agent describes what it needs in natural language and another agent responds in kind. Discovery, capability description, and ad-hoc invocation can all happen this way.
* **Co-designed structured formats** where two agents negotiate a schema for a specific exchange and use it for the duration. The schema can be cached by the participants and reused indefinitely without renegotiation.
* **De facto conventions** that emerge across many participants and become widely adopted without being baked into Wires itself. MCP is an existing convention of this kind that predates Wires; others will emerge.

Crystallization of negotiated patterns happens at the agent level rather than at a registry — agents that discover and use a particular pattern cache it locally and reuse it without renegotiation. The substrate does not impose a registry. Where high-value patterns are clear in advance, the project may publish standardized message formats to accelerate adoption; these are conventions on top of the substrate, not part of the substrate spec. Channel metadata is also available for participants to record agreements ad-hoc where doing so is useful.

A consequence of this position is that Services participating in the fabric typically need an agentic surface — sufficient to describe themselves and engage in basic negotiation — even when backed by deterministic code. The thermostat firmware does not have this; the thermostat's Service node, which represents the firmware on the fabric, does.

### **Worked example: CLI over Wires**

To make the substrate's intent concrete: imagine a CLI exposed via a Wires channel.

A Service node hosts a command-line program and exposes it on a channel within a fabric. An authorized agent that joins the channel drives the CLI as if it had local shell access — sending commands, receiving stdout, stderr, and exit codes as messages on the channel. The agent learns the CLI's surface from `--help` and uses it directly from there.

The pattern fits Wires unusually well. CLIs are self-documenting, have stable error semantics, and are interfaces agents already handle exceptionally well. Identity, authorization, encryption, and audit fall out of the substrate: the agent's right to drive the CLI is its presence in the channel roster, and revocation propagates simply by removing the ability to publish to the channel. The CLI process trusts the substrate to enforce access; it does not need to reimplement auth.

The contrast with SSH is instructive. SSH brings its own identity, requires point-to-point reachability, and grants a raw shell unless constrained. CLI-over-Wires inherits Iroh identity, needs no public reachability, and is scoped to the program exposed on the channel. Multiple authorized agents can observe or collaboratively drive a single session, enabling delegation, agent collaboration, and replayable audit.

The project will publish a standardized message format for this pattern so that agents and CLI-exposing Services interoperate without negotiation. This is the project-published convention path noted above — a layer on top of the substrate, not part of the substrate spec.

## **Integration with existing systems**

A working MCP gateway exists that exposes a Wires fabric to MCP-speaking clients, including Claude. The gateway runs as a Node within the fabric. Sign-in to the gateway from an MCP client uses the same pairing flow as any other Node joining the fabric.

The gateway is a concrete instance of the conventional-RPC pattern described in the previous section: MCP is a pre-existing protocol that emerged before Wires, and the gateway supports it on the substrate without requiring changes to the MCP specification. The integration matters for two reasons. First, it provides an adoption path that does not require ecosystem replacement; existing MCP-speaking clients can use Wires fabrics today. Second, it makes the substrate's relationship to existing protocols concrete: MCP is one negotiation outcome among many that Wires accommodates, not a thing Wires replaces. Future Wires-native clients can address fabric capabilities directly without the gateway, accessing the agent-to-agent and human-to-agent patterns MCP does not address.

## **Adjacent work**

Wires composes well-understood primitives into an opinionated stack:

* **Iroh** provides the transport, identity, and gossip substrate. Iroh's dial-by-public-key model keeps public internet surface area minimal.
* **Group keying with epoch advance on membership change** is the same pattern formalized by MLS and used in modern secure messaging systems. Wires applies it per-channel.
* **Capability-style authorization expressed as channel membership** is structurally similar to object-capability systems and to capability tokens like UCAN, with the simplification that channel-level authority is roster presence rather than a standalone transferable artifact.
* **Encrypted append-only logs replayable to authorized parties** is a pattern shared with several encrypted-collaboration systems.

What is novel in Wires is not the components but the orientation. The fabric is rooted in the human rather than in any service. Services join the human's network rather than the inverse. The opinionated combination — user-rooted identity, hardware-bound root, two-layer authorization with non-transferable fabric grants and roster-based channel membership, hosted relay with no plaintext access, MCP gateway as a working integration — is the deployable form of a model the constituent technologies enable but do not specify.

## **Open design questions**

The following are deliberately unresolved at the current stage and will be addressed as the implementation matures:

* **Capability vocabulary.** Coarse roles such as owner, member, and read-only are present; finer-grained permission expression for specific message kinds and access patterns is open.
* **Negotiation memory and crystallization mechanisms.** Agents that negotiate communication patterns cache the outcomes locally; whether and how to support shared registries, fabric-level metadata for recording agreements, or cross-agent learning is open.
* **Cross-fabric connectivity.** Household, organizational, and shared-resource scenarios will be addressed as a composition layer over the single-human fabric model rather than by changing the fabric primitive.
* **Node type strictness.** Whether the Human/Agent/Service taxonomy remains advisory or acquires protocol-level meaning is open.
