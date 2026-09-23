# Lane 1 — Incumbent Messaging Platforms as Habitats for AI Agents

*Research agent output, verbatim. Current to 2026-08-15. Part of the [agent-comms market research](./synthesis.md).*

## Slack

**Integration model**
- Agents are apps with bot users: own identity, can join channels when invited, respond in DMs/threads/channels, with a dedicated "Agents & Assistants" surface (split-view AI pane, suggested prompts, status updates) since 2024 (https://api.slack.com/docs/apps/agents-assistants-overview, https://docs.slack.dev/ai/).
- Agents can read thread/channel history via scoped APIs, take actions (create channels, lists, canvases), and be @-mentioned. Access is scope-gated per app install (https://slack.com/help/articles/33076000248851-Work-with-AI-agents-in-Slack).
- Dreamforce 2025: Salesforce rebranded Slack as "the agentic OS" — "the conversational interface for humans and agents." New Real-Time Search (RTS) API + a Slack MCP server let third-party agents (OpenAI, Anthropic, Google, Perplexity, Writer, Cognition, Cursor, etc.) query Slack context on demand (https://slack.com/blog/news/ai-innovations-in-slack, https://www.salesforce.com/news/stories/slack-context-aware-ai-apps-agents/, https://slack.com/blog/news/mcp-real-time-search-api-now-available). RTS/MCP went GA in 2026 after closed beta (https://docs.slack.dev/apis/web-api/real-time-search-api/, https://docs.slack.dev/ai/using-data-access-api/).

**Constraints / trajectory**
- May 29, 2025 API ToS change: prohibits bulk export via API, persistent copies/indexes/long-term stores of Slack data, and any use of API-accessed data for LLM training (https://www.computerworld.com/article/4005509/salesforce-changes-slack-api-terms-to-block-bulk-data-access-for-llms.html, https://natlawreview.com/article/salesforce-locks-down-slack-data-time-review-your-slack-api-terms).
- Non-Marketplace apps: `conversations.history`/`conversations.replies` throttled to 1 request/min, 15 messages/request — effectively killing external indexing (Glean-style) outside sanctioned channels (https://api.slack.com/changelog/2025-05-terms-rate-limit-update-and-faq, https://cloudwars.com/cloud-wars-minute/slack-api-terms-update-restricts-data-exports-and-llm-usage/).
- The replacement (RTS API) keeps data inside Slack: query-by-query retrieval only, short-lived tokens, no external persistence — i.e., Slack becomes the toll gate for its own conversational context (https://api.slack.com/docs/apps/data-access-api, https://slack.dev/secure-data-connectivity-for-the-modern-ai-era/).
- Marketplace is declared the only legitimate channel for commercial distribution, including "unlisted" custom apps (https://api.slack.com/changelog/2025-05-terms-rate-limit-update-and-faq).

**Complaints**
- Ask HN (2026): "Slack AI already vectorizes all messages for semantic search internally. But there's no developer API to query it" — teams rebuild embedding pipelines (pgvector etc.) to give agents memory Slack already has; agents "can write but can't remember" (https://news.ycombinator.com/item?id=47285781).
- HN platform-risk thread ("I pay Slack $50k/year. They have no reason to shut me off."): commenters flag repricing risk ("your 1000 clients would cost you $180,000 a year"), the new API terms reaching internal apps, and XMPP-era precedent for walled-garden turns (https://news.ycombinator.com/item?id=46674123).
- Press framing: "Salesforce banned LLMs from Slack, then let one in" — restrictions land selectively while Agentforce/partners get privileged access (https://techtrenches.dev/p/salesforce-locked-slack-for-privacy).

**Notable agents**: Claude in Slack (Oct 2025), Claude Code from Slack threads (Dec 2025 beta — @-mention Claude in a bug thread, it opens a PR), "Claude Tag" deeper MCP-based two-way integration (June 2026) (https://venturebeat.com/ai/anthropics-claude-code-can-now-read-your-slack-messages-and-write-code-for, https://www.salesforceben.com/anthropic-and-salesforce-announce-new-claude-to-slack-integration/). Agentforce agents run natively in channels/DMs (https://slack.com/ai-agents).

**E2EE**: None; explicitly abandoned in 2018 in favor of EKM (customer-held keys, but Slack servers still decrypt at runtime for search/AI/integrations). E2EE was rejected precisely because it breaks search, integrations, and AI grounding (https://www.computerworld.com/article/1720408/slack-rolls-out-enterprise-key-management-but-has-no-plans-for-end-to-end-encryption.html, https://vanishingvault.com/blog/is-slack-encrypted).

## WhatsApp

**Integration model**
- No consumer bot API. Automation only via WhatsApp Business Platform (Cloud API): business-initiated messages require pre-approved templates; free-form replies only inside a 24h customer-service window; customer must generally opt in / initiate (https://developers.facebook.com/documentation/business-messaging/whatsapp/about-the-platform).
- Groups API exists as of 2026 but is gated to businesses with 100k+ monthly business-initiated conversations, max 8 participants per group, OBA required — not a general group-chat habitat for agents (https://developers.facebook.com/documentation/business-messaging/whatsapp/groups, https://sanuker.com/whatsapp-groups-api-en/).

**Constraints / trajectory (the big one)**
- Oct 15, 2025 policy (enforced Jan 15, 2026): Meta bans "general-purpose AI chatbots" from the Business API — LLM providers/AI assistants are prohibited "when such technologies are the primary functionality." Structured task bots (support, bookings, order tracking) remain allowed (https://respond.io/blog/whatsapp-general-purpose-chatbots-ban, https://dig.watch/updates/meta-changes-whatsapp-terms-to-block-third-party-ai-assistants).
- Casualties: ChatGPT on WhatsApp (~50M users) and Microsoft Copilot forced off Jan 15, 2026; OpenAI published a migration path off WhatsApp (https://openai.com/index/chatgpt-whatsapp-transition/, https://www.forbes.com/sites/davidphelan/2025/10/22/whatsapp-to-lose-chatgpt-integration-for-50-million-users-heres-what-to-do/). Meta's stated reason: these bots generated massive traffic without Business-Platform revenue; press framing: "Meta wants to win the AI race by kicking competitors out of its platform" (https://www.phonearena.com/news/meta-wants-to-win-the-ai-race-by-kicking-its-competitors-out-of-its-platform_id176121). Meta AI stays, obviously.
- Pricing: switched from conversation-based to per-message pricing July 1, 2025 (marketing $0.025–$0.1365/msg; utility/auth $0.004–$0.0456/msg); further tightening scheduled — charging for service messages and in-window utility from Oct 1, 2026 (https://www.ycloud.com/blog/whatsapp-api-pricing-update, https://blueticks.co/blog/whatsapp-business-api-pricing-2026). Every agent utterance has a metered price set by Meta.
- Template review/rejection and account-ban opacity are chronic developer complaints (https://docs.aws.amazon.com/social-messaging/latest/userguide/managing-templates_rejection.html).

**E2EE**: Consumer chats are Signal-protocol E2EE, but Business Cloud API messages are decrypted at Meta's Cloud API endpoint and forwarded to the business — E2EE effectively terminates at Meta's server for any bot conversation (https://www.infobip.com/blog/whatsapp-data-security, https://developers.facebook.com/documentation/business-messaging/whatsapp/data-privacy-and-security/). For its own AI, Meta built "Private Processing" (TEE/confidential-VM offload) to claim E2EE-compatible AI features — an accommodation available to Meta AI, not to third-party agents (https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/, https://beebom.com/whatsapp-private-processing-meta-ai-push-undermine-privacy/).

## Discord

**Integration model**
- Most bot-native incumbent: bots are first-class users with their own identity, can join servers, read/send in channels, slash commands, components, Activities (https://docs.discord.com/developers/change-log).
- But: message content is a privileged intent since Aug 2022 — bots in 75+ (now 100+) servers must pass manual review with a documented need; "if your functionality can be achieved via slash commands, you'll be rejected" (https://github.com/discord/discord-api-docs/discussions/5412, https://support-dev.discord.com/hc/en-us/articles/4404772028055). An always-listening ambient agent in large servers is approval-gated.
- Bots can't DM users unless they share a server; no cross-server identity continuity for conversations.

**Economics**
- Premium Apps: native subscriptions/one-time purchases, 30% platform fee (15% "Growth Tier" on first $1M); new Monetization Requirements policy forces devs selling paid bot features to also sell through Discord's rails at no higher price than external channels (https://discord.com/blog/premium-app-subscriptions-for-discord-developers, https://support-dev.discord.com/hc/en-us/articles/23810643331735, https://docs.discord.com/developers/platform/app-monetization).
- Discord's own AI persona Clyde (OpenAI-powered) was killed Dec 1, 2023 with no explanation after limited beta (https://decrypt.co/206528/clydes-last-call-discords-ai-chatbot-being-shut-down-on-december-1). Discord's 2026 platform focus is games/Activities/Social SDK, not agents (https://www.jotme.io/blog/discord-update).
- Thriving third-party AI bot ecosystem regardless: Midjourney (born on Discord), MEE6, Botpress/Voiceflow-built agents, support bots (https://www.eesel.ai/blog/discord-ai).

**E2EE**: DAVE protocol — audited, open E2EE for voice/video calls (2024). Text (channels and DMs) is explicitly not E2EE (https://www.eff.org/deeplinks/2024/09/discords-end-end-encryption-voice-and-video-step-forward-privacy-all).

## Telegram

**Integration model**
- Most open bot platform: free, public Bot API since 2015; bots have their own identity, join groups, inline mode, mini apps, payments; Durov positions chat as "a natural interface for AI" and touts "the most powerful API" (https://simone.app/blog/ai-available-on-telegram).
- Structural limits: bots cannot initiate DMs with users (anti-spam — user must message first); default "privacy mode" means group bots only see commands/@-mentions/replies unless the admin disables it (https://www.teleme.io/articles/group_privacy_mode_of_telegram_bots?hl=en, https://grokipedia.com/page/Telegram_Bot_API_Limitations). Real-world agent projects hit this constantly (e.g. mention-handling bugs under privacy mode: https://github.com/openclaw/openclaw/issues/28085).

**Economics / trajectory**
- xAI agreed to pay Telegram $300M for a 1-year Grok distribution deal (May 2025) — the inverse of WhatsApp's model: the AI company pays the platform for distribution; the integration then reportedly stalled (https://durovscode.com/why-telegram-grok-no-deal).
- Stars currency + mini-app monetization + developer-set affiliate revenue shares; CAC claimed 90–95% below app stores; many third-party AI bots (Perplexity, Manus, Copilot-on-Telegram, dozens of wrappers) operate freely (https://merge.rocks/blog/telegram-mini-apps-2026-monetization-guide-how-to-earn-from-telegram-mini-apps, https://telegram.org/blog/affiliate-programs-ai-sticker-search, https://www.phonearena.com/news/microsofts-copilot-ai-chatbot-arrives-on-telegram_id158794).

**E2EE**: Cloud chats (everything bots can touch) are server-side encrypted only, not E2EE; E2EE exists solely in opt-in 1:1 Secret Chats, which bots cannot participate in. Openness to bots is purchased by Telegram holding plaintext.

## Microsoft Teams

**Integration model**
- Heaviest agent investment of any incumbent, entirely Copilot-centric: Microsoft 365 Agent Store (discover/install agents), role agents (Facilitator, Interpreter, Project Manager) that behave like team members in meetings/chats, agents callable via MCP, Copilot Studio + Azure AI Foundry for building (https://www.microsoft.com/en-us/microsoft-cloud/blog/2025/09/25/empower-your-workforce-with-agents-in-microsoft-365-copilot/, https://learn.microsoft.com/en-us/microsoft-365/copilot/copilot-agent-store).
- Real agent-identity model: Entra Agent ID — every agent gets a unique directory identity with scoped access; Agent 365 (Nov 2025) is a full "control plane" for agent fleets (registry, governance, security policy) (https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/). This is the most complete answer to "agents as first-class org members" among incumbents — but it is tenant-bound and admin-mediated.
- Friction: proactive messaging requires the bot to be installed for the user/team plus Entra admin consent; non-admin users hit "requires admin approval" walls; Graph can only install apps from the org store or Teams Store (https://learn.microsoft.com/en-us/microsoftteams/platform/graph-api/proactive-bots-and-messages/graph-proactive-bots-and-messages). Bot Framework SDK is being retired in favor of the M365 Agents SDK, forcing migrations (https://learn.microsoft.com/en-us/microsoft-365/agents-sdk/bf-migration-guidance).

**Adoption reality check**
- Paid M365 Copilot seats ~15M as of Jan 2026 — ~3.3% of 450M commercial M365 users; ~1% weekly usage by one analysis; accuracy NPS fell to -24.1 (Sept 2025); only 8% of users prefer Copilot over ChatGPT/Gemini when given a choice; data-governance/oversharing fear is the top enterprise blocker (https://www.windowslatest.com/2026/07/07/microsoft-365-copilot-adoption-is-under-4-5-after-3-years-only-1-use-it-weekly-yet-prices-went-up/, https://www.nojitter.com/ai-automation/4-obstacles-impede-paid-microsoft-365-adoption, https://latitude.so/blog/microsoft-copilot-ai-performance-reliability-issues).

**E2EE**: Only optional 1:1 calls; chat/channel content is not E2EE (necessarily — Copilot grounds on it).

## iMessage / SMS (brief)

- No public iMessage bot API at all; unofficial Mac-bridge hacks only (https://www.clawmessenger.com/blog/imessage-bot). Apple Messages for Business (via approved partners) is strictly customer-initiated — businesses/bots cannot reach out first (https://www.infobip.com/blog/rcs-vs-imessage).
- First crack: Poke (The Interaction Company), launched Mar 2026, approved by Apple ~June 4, 2026 as the first third-party proactive AI agent on Messages for Business — email triage, scheduling, smart-home, usage-negotiated pricing; still requires the user to opt in via phone number (https://appleinsider.com/articles/26/06/04/first-ai-agent-for-messages-business-chat-approved-by-apple).
- RCS: Apple added RCS in iOS 18; RCS for Business rolling out on iPhone; RCS allows business-initiated messaging (push, unlike iMessage's pull); E2EE for cross-platform personal chats only began beta rollout in iOS 26.5 (May 2026) (https://sinch.com/blog/apple-support-rcs/, https://www.infobip.com/blog/apple-rcs). SMS/A2P remains carrier-registered (10DLC), template-ish, and identity-poor. iMessage 1:1/ADP chats are E2EE; nothing bot-accessible is.
- Signal: deliberately no bot API, ever — privacy stance; only unofficial signal-cli hacks (https://alexasteinbruck.medium.com/bot-development-for-messenger-platforms-whatsapp-telegram-and-signal-2025-guide-50635f49b8c6).

---

## Cross-cutting observations

**What structurally works on incumbents**
- Distribution and habit: agents that live where users already talk get instant reach (ChatGPT hit 50M users on WhatsApp with zero app installs; Claude Code in Slack turns a bug thread into a PR).
- The chat thread is a proven UX for agent interaction — every platform converged on @-mention + thread + status updates.
- Discord and Telegram prove third-party bot ecosystems flourish when bots get real identity, group membership, and free/cheap APIs.
- Microsoft is validating the concept of agent identity as directory citizenship (Entra Agent ID / Agent 365): agents as governable org members, not webhooks.
- MCP/A2A emerging as cross-platform plumbing: Slack shipped an MCP server; Teams agents call MCP tools; A2A has 150+ orgs and Linux Foundation governance (https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year).

**What's structurally broken**
1. **The platform owns the context, and increasingly rents it.** Slack banned persistent external copies and throttled history APIs, then sold the replacement (RTS/Data Access API) as query-only access. Agents on Slack literally cannot remember — memory is a platform-controlled service (HN: https://news.ycombinator.com/item?id=47285781).
2. **Incumbents demote third-party AI to second class whenever it competes with their own.** WhatsApp banned general-purpose AI bots while keeping Meta AI; Slack restricted LLM use of API data while wiring in Agentforce and paid partners; Teams routes everything through Copilot. Rule access is asymmetric by design.
3. **No portable agent identity.** An agent is a Slack app in Slack, an Entra object in Teams, a bot user in Discord/Telegram, a business phone number on WhatsApp, nothing on iMessage/Signal. Identity, permissions, memory, and reputation reset at every platform boundary; nothing federates.
4. **Agent-to-agent communication inside chat platforms is essentially unsupported.** Platforms model bots as endpoints for humans; bots messaging bots is ignored (Telegram bots can't see other bots' messages by default; Discord bots commonly filter bot messages to avoid loops; WhatsApp has no concept of it). A2A exists as an enterprise backend protocol, not as something that runs inside any consumer messaging fabric.
5. **E2EE and agents are currently mutually exclusive everywhere.** Every bot-accessible surface is plaintext-to-the-platform: Slack/Teams/Discord-text (no E2EE), Telegram cloud chats (no E2EE), WhatsApp Business API (E2EE terminates at Meta's cloud endpoint). The only "E2EE + AI" construction shipping is Meta's Private Processing TEEs — proprietary and reserved for Meta's own assistant. Signal's answer is to have no bots at all. Nobody offers E2EE group chat where an agent is a cryptographic member.
6. **Proactivity is rationed.** Telegram bots can't initiate; iMessage business chat is pull-only; Teams needs install + admin consent; WhatsApp charges per template message. An agent that notices something and speaks up first — the core of "agent as participant" — is either impossible, admin-gated, or metered.
7. **Platform risk is priced into everything.** May-2025 Slack ToS retroactively rate-limited existing apps; WhatsApp gave AI providers ~3 months' notice to abandon 50M users; Clyde vanished without explanation; Bot Framework devs are being forced to migrate SDKs. Developers on HN explicitly reason about repricing, acquisition, and shutoff risk as a cost of building on these platforms (https://news.ycombinator.com/item?id=46674123).

## Five strongest signals on unmet need

1. **Meta expelling ChatGPT/Copilot/Perplexity from WhatsApp (Jan 15, 2026) stranded ~50M+ users of AI-in-chat.** Demonstrated demand at scale for AI inside a personal messenger, and simultaneous proof that no incumbent will host competitors' agents neutrally. The demand exists; the habitat was revoked (https://openai.com/index/chatgpt-whatsapp-transition/).
2. **Slack's 2025 data lockdown plus the developer response.** Salesforce restricting history APIs to 15 msgs/min and banning external stores — then monetizing query-only access — while devs publicly beg for a `semantic.search` endpoint so agents can have memory, is direct evidence that "agents as full participants with durable context" is something the incumbent structurally withholds (https://api.slack.com/changelog/2025-05-terms-rate-limit-update-and-faq, https://news.ycombinator.com/item?id=47285781).
3. **The E2EE/agent void.** No platform on Earth currently offers end-to-end-encrypted group conversation with an AI agent as a cryptographic member; Meta's TEE workaround (Private Processing) is the sole attempt and is closed and first-party-only. If private human+agent group communication matters, incumbents cannot deliver it without re-architecting their business (https://engineering.fb.com/2025/04/29/security/whatsapp-private-processing-ai-tools/, https://www.eff.org/deeplinks/2024/09/discords-end-end-encryption-voice-and-video-step-forward-privacy-all).
4. **Microsoft built directory-grade agent identity (Entra Agent ID, Agent 365) — and its flagship agent still shows <5% paid adoption and ~1% weekly use.** The identity/governance concept is validated as necessary; the incumbent's Copilot-locked, admin-mediated, single-tenant execution is underperforming. First-class agent identity that crosses org and platform boundaries remains unbuilt (https://www.microsoft.com/en-us/microsoft-365/blog/2025/11/18/microsoft-agent-365-the-control-plane-for-ai-agents/, https://www.windowslatest.com/2026/07/07/microsoft-365-copilot-adoption-is-under-4-5-after-3-years-only-1-use-it-weekly-yet-prices-went-up/).
5. **Counter-signal to weigh honestly: Telegram and Discord show "open enough" may already satisfy much of the market.** Telegram hosts dozens of AI assistants freely, got xAI to pay $300M for placement, and monetizes bots natively; Discord sustains a large paid bot economy. The unmet need is therefore not "any habitat for bots" — it is specifically (a) agents in *private/E2EE* contexts, (b) agents with *portable identity and memory* across platforms, (c) *agent-initiated* and *agent-to-agent* participation, and (d) freedom from unilateral policy revocation. Those four properties are unserved by every incumbent; general bot hosting is not (https://durovscode.com/why-telegram-grok-no-deal, https://discord.com/blog/premium-app-subscriptions-for-discord-developers).

*Method note: all claims sourced via live web search Aug 2026; primary platform docs cited where available. Weakest-sourced areas: WhatsApp developer-ban complaints (thin Reddit retrieval) and Slack RTS API pricing (not yet public).*
