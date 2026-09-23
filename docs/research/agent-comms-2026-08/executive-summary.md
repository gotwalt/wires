# Wires — Executive Summary (plain-language)

*2026-08-15. Non-technical distillation of [synthesis.md](./synthesis.md).*

## The problem

AI assistants have stopped being tools you open and become **participants you talk to**. Millions of people now text their AI assistant the way they text a friend — and increasingly they're adding those assistants to *group* conversations: a family chat that plans trips, a couple managing a shopping list, a work team doing standups.

But every chat system these assistants live in was built for humans only. The assistant is a hack bolted onto the side. That creates three problems people are already getting burned by:

1. **You can't see what it can see.** In a group chat, nobody but the owner knows what the assistant has access to, what it remembers, or who it talks to. One user's assistant chatted with other bots and leaked his wife's holiday plans. When Meta forced its AI into WhatsApp groups with no way to remove it, users revolted and fled to Signal.
2. **You can't really take access away.** When an AI tool at a chat company got hacked last year, attackers used its stored credentials to raid data from 700+ companies — and the only fix was to shut the whole thing off, everywhere, for everyone. There's no way to just remove one assistant from one conversation and *know* it's out.
3. **You can't trust its account of itself.** AI assistants misreport what they did — one famously deleted a company's database and then fabricated records to cover it. The only log of what happened is often kept by the assistant itself, or by a platform with its own interests.

## The value proposition

**Wires is a group conversation where everyone — people and AI assistants alike — is a real, named member with their own key to the room.**

Concretely, that means three things no chat product offers today:

- **A visible guest list.** Everyone in the conversation can see exactly who's in it — which humans, which assistants, and what each assistant is allowed to do. An assistant is always itself, never disguised as its owner.
- **A lock, not a policy.** Membership is enforced by encryption, not by a company's promise. Remove an assistant (or a person) and the room's keys change — they are mathematically locked out from that moment, and you can prove it. Nobody outside the room, including whoever runs the servers, can read anything.
- **A record no one can rewrite.** The conversation itself is the tamper-proof log of who said and did what. You don't have to trust the assistant's version of events, or the platform's.

One sentence: *Wires is the room your AI assistant lives in — everyone in it is a named member with a key, everyone can see who's there, and when you remove someone, you can prove they're gone.*

## How it fits the market

**We are not competing with WhatsApp or Slack for human conversations.** That fight is lost before it starts. Instead, Wires serves a fast-growing group the big platforms structurally *cannot* serve: people who run their own AI assistants and want to share them with a family or a team.

- **The demand side just materialized.** The fastest-growing open-source project in GitHub's history is exactly this — a personal AI assistant you text. Hundreds of thousands of people run one. They're already putting them in family and team group chats using duct tape and config files, and asking (in public forums, in these words) for "a shared family chat with the bot, plus private chats for each member" — which is precisely what Wires provides. Its first product is a simple way to plug one of these existing assistants into a Wires room.
- **The incumbents can't follow.** Slack, WhatsApp, Teams, and Discord all read your messages as part of their business model — search, ads, their own AI features depend on it. A truly locked room breaks their model. Meanwhile they've shown they'll evict competitors at will: Meta kicked ChatGPT (50M users) off WhatsApp this January; Slack banned outside tools from keeping message history.
- **The direct competitors skipped the hard part.** Jack Dorsey's company launched "Buzz" this July — group chat for teams and their AI agents, very close to our idea — but without encryption: the operator of the server can read everything. The privacy-first player, Signal, has publicly refused to allow AI assistants at all. The seat between them — assistants welcomed *and* the room actually private and provable — is empty.

## Why now

1. **The behavior exists but the product doesn't.** People started sharing AI assistants with their families and teams roughly nine months ago. They're improvising on top of Telegram and Signal, and hitting exactly the failures Wires prevents. Being the missing layer under an existing behavior is a far better position than inventing a new one.
2. **Trust just broke in public.** The past year delivered the incidents — the 700-company credential breach, the database-deleting assistant, a wave of AI-tool hacks — that turned "who can this assistant reach, and can I revoke it?" from a theoretical question into one businesses and families now ask.
3. **Regulators arrived this month.** EU rules that took full effect August 2, 2026 require organizations to keep reliable records of what their AI systems did. A conversation that is its own tamper-proof record is arriving exactly when people are obligated to produce one.
4. **The window is open but won't stay open.** The category (group chat for humans + AI) was validated this summer by Block, Anthropic, and Y Combinator all launching or funding versions of it — none with real privacy or provable membership. The first credible product to occupy that gap defines it.
