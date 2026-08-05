//! The structural claims of the documents a stranger reads first, and of the
//! policy documents a contributor is held to.
//!
//! # Why these criteria needed a program
//!
//! AC-7.16 and AC-7.18 through AC-7.24 are all statements about what a
//! document contains: a limitations section that says why identification
//! coverage is thin, an authorized-use statement above the fold, a quickstart
//! that cannot be followed without writing a scope manifest, a clean-room
//! attestation, a Windows position stated as a licensing constraint, evasion
//! and anonymization named as non-goals, a clean-room rule stated for
//! contributors with a citation requirement that says what a citation must be
//! checkable *against*, and a disclosure contact with a response time.
//!
//! Every one of them would have been closed by a person reading the file and
//! saying so, and this project's Global Constraints are explicit that manual
//! verification does not close a criterion: *a criterion is closed by a named
//! test that dies when the thing it names is removed, and by nothing else.*
//! Documentation is not exempt from that -- it is the part of the repository
//! with the *worst* record here. `README.md` was factually wrong at three
//! consecutive milestone exits and twice inside the fixes for those reviews.
//!
//! # What this can see, and what it cannot
//!
//! It can prove a section exists, is where it is supposed to be, and states
//! the specific thing its criterion requires. It cannot prove the section is
//! *true*. `NOT MECHANICALLY CHECKED` at the bottom of this file is written
//! out for the same reason [`crate::readme`]'s is: a green check must not be
//! read as "the documentation is correct", only as "these claims are present
//! and in the right place".
//!
//! # Relationship to the other two document checkers
//!
//! Three checkers read prose and they divide by question, not by file:
//!
//! - [`crate::readme`] -- **is this number true?** README only, against the
//!   tree.
//! - [`crate::phrases`] -- **is this pattern forbidden anywhere?** The whole
//!   repository, including the positioning rule that discharges AC-7.17.
//! - this module -- **does this document still say the thing its acceptance
//!   criterion requires, in the place it requires?**

use std::path::Path;

use regex::Regex;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// One thing a document must say, and the criterion that says so.
pub struct Claim {
    /// The document, repository-relative.
    pub path: &'static str,
    /// The acceptance criterion this discharges, named in every failure so a
    /// red build is adjudicable without opening this file.
    pub criterion: &'static str,
    /// What is required, in one line -- the text a failing build shows.
    pub requirement: &'static str,
    /// A `regex` expression matched against the document's *flattened* text
    /// (see [`flatten`]), so hard wrapping is irrelevant.
    pub pattern: &'static str,
    /// Why this specific sentence is load-bearing rather than nice to have.
    /// Printed with the failure, so a contributor who trips the check reads
    /// the reasoning instead of guessing at it.
    pub because: &'static str,
}

const README: &str = "README.md";
const DESIGN_PAPER: &str = "docs/design-paper.md";
const PLATFORM: &str = "docs/platform-support.md";
const THREAT_MODEL: &str = "docs/threat-model.md";
const SECURITY: &str = "SECURITY.md";
const CONTRIBUTING: &str = "CONTRIBUTING.md";
const CONDUCT: &str = "CODE_OF_CONDUCT.md";
/// The issue-template directory, and the one template whose text carries a
/// criterion. `.github/ISSUE_TEMPLATE/` is a directory rather than a document,
/// so what is checkable about it is that the templates a criterion depends on
/// exist and still say the thing — [`check_docs`] reads this path like any
/// other document.
const FEATURE_TEMPLATE: &str = ".github/ISSUE_TEMPLATE/feature_request.md";
const RULE_TEMPLATE: &str = ".github/ISSUE_TEMPLATE/interpretation_rule.md";

/// Every document this module reads, in the order it reports on them.
pub const DOCUMENTS: &[&str] = &[
    README,
    DESIGN_PAPER,
    PLATFORM,
    THREAT_MODEL,
    SECURITY,
    CONTRIBUTING,
    CONDUCT,
    FEATURE_TEMPLATE,
    RULE_TEMPLATE,
];

pub const CLAIMS: &[Claim] = &[
    // --- AC-7.16: the limitations section -------------------------------
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "a limitations section exists, under that heading",
        pattern: r"(?i)#+ Limitations",
        because: "Every other claim here is scoped to that section. Without the heading the \
                  section is prose scattered through the file, and a reader looking for the \
                  honest part has nowhere to look.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the identification gap against Nmap is stated with its cause",
        pattern: r"(?i)28 years of accumulated community fingerprint",
        because: "The criterion is not 'admit we are behind' -- it is state the asymmetry and \
                  explain it. 28 years of contributions against eight protocols is the \
                  explanation, and it is the one a reader can check.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the TLS identification gap is stated as a measured, structural loss",
        pattern: r"(?i)identified only as `tls`",
        because: "This is the single most concrete identification loss this project has: on \
                  10.30.0.17:443 `nmap -sV` names the product and bathy does not. It is \
                  recorded in lab/ground-truth.json as `identification_gap`, so it is measured \
                  rather than estimated, and a limitations section that omits it is a \
                  limitations section that omits the thing a reader running the benchmark \
                  will find first.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the first half of the TLS gap's cause: detect_service stops at the first \
                      probe that interprets",
        pattern: r"(?i)stops at the first probe whose capture interprets to anything",
        because: "Without the cause, the gap reads as a missing fingerprint that a contributor \
                  could add. It is not: it is a policy in `detect_service`, and changing it \
                  changes per-endpoint packet accounting, pacing, and the reported service for \
                  every TLS port. Naming the cause is what stops the wrong fix.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the second half of the TLS gap's cause: RFC 8446 encrypts the certificate",
        pattern: r"(?i)RFC 8446 encrypts the certificate",
        because: "`tls-v1` is protocol-only BY CONSTRUCTION, not by omission -- there is no \
                  product name in a TLS 1.3 handshake to read. Stated as its own claim because \
                  half the cause explains nothing: first-match alone sounds like a tunable, and \
                  the encryption alone sounds like a rule someone could add.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the reproducibility distinction is stated in its scoped form",
        pattern: r"(?i)Observations are not reproducible\. Planning and interpretation are",
        because: "The Global Constraint forbids the unscoped determinism claim and requires \
                  this distinction to be explained rather than asserted. `check-phrases` \
                  catches the forbidden phrasing; nothing but this catches the required one \
                  going missing.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "port presets are stated as heuristics, not measurements",
        pattern: r"(?i)IANA-derived heuristics, not prevalence measurements",
        because: "A `top-100` list invites the reading 'the hundred ports most likely to be \
                  open'. Nothing here measured that, and saying so is cheaper than being \
                  found out.",
    },
    // The five absences the plan names, one claim each rather than one
    // pattern spanning all five. Individually, a failure says WHICH one went
    // missing; together, the check would only say "the list changed" -- and
    // the bounded-gap regex it needed was also, measurably, the most
    // expensive pattern in this file.
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the absence of OS detection is stated",
        pattern: r"(?i)\*\*No OS detection\.\*\*",
        because: "The plan names it. A reader may reasonably assume a scanner fingerprints \
                  operating systems, and an assumption that goes uncorrected is a defect we \
                  caused.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the absence of UDP scanning is stated",
        pattern: r"(?i)\*\*No UDP\.\*\*",
        because: "`Transport::Udp` exists in the type system, which makes this the absence a \
                  reader is most likely to get wrong by reading the schemas. No planner emits \
                  it and no probe speaks it.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the absence of traceroute is stated",
        pattern: r"(?i)\*\*No traceroute\*\*",
        because: "Named in the plan, and the whole class -- path and topology discovery -- goes \
                  with it.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the absence of IPv6 scanning is stated",
        pattern: r"(?i)\*\*No IPv6\.\*\*",
        because: "And it is refused rather than unimplemented, which is a stronger statement \
                  than 'not supported' and the one a reader needs: no manifest can authorize an \
                  IPv6 address in v0.1.",
    },
    Claim {
        path: README,
        criterion: "AC-7.16",
        requirement: "the absence of Windows support is stated",
        pattern: r"(?i)\*\*No Windows\.\*\*",
        because: "With the pointer to docs/platform-support.md, where AC-7.21 requires the \
                  reason to be stated as the licensing constraint it is.",
    },
    // --- AC-7.18: authorized use, above the fold ------------------------
    Claim {
        path: README,
        criterion: "AC-7.18",
        requirement: "an authorized-use statement exists",
        pattern: r"(?i)#+ Authorized use",
        because: "It is the first thing this project owes anyone who runs it.",
    },
    Claim {
        path: README,
        criterion: "AC-7.18",
        requirement: "the statement says scanning without authorization may be unlawful",
        pattern: r"(?i)without authorization may be unlawful",
        because: "'Be careful' is not a statement; naming the consequence and whose it is, is. \
                  The sentence also has to say the responsibility is the operator's, which the \
                  next claim checks.",
    },
    Claim {
        path: README,
        criterion: "AC-7.18",
        requirement: "the statement places responsibility on the operator",
        pattern: r"(?i)your responsibility, not the tool's",
        because: "A tool that implies it will stop you scanning something you should not is \
                  making a promise it cannot keep. Scope enforcement enforces a manifest; it \
                  does not know whether the manifest is honest.",
    },
    // --- AC-7.19: the quickstart requires a manifest --------------------
    Claim {
        path: README,
        criterion: "AC-7.19",
        requirement: "the quickstart exists",
        pattern: r"(?i)#+ 60-second quickstart",
        because: "A README with no runnable path is a README nobody executes, and an \
                  unexecuted quickstart is the single most likely wrong thing in a repository.",
    },
    Claim {
        path: README,
        criterion: "AC-7.19",
        requirement: "the quickstart writes a scope manifest",
        pattern: r"cat > quickstart-scope\.json",
        because: "AC-7.19 is not 'mention that a manifest is needed'. The quickstart must not \
                  be completable without creating one, because the tool genuinely cannot be \
                  used without one. Verified by execution as well: omitting `--scope` fails in \
                  argument parsing at exit 1.",
    },
    Claim {
        path: README,
        criterion: "AC-7.19",
        requirement: "the manifest the quickstart writes carries an expiry",
        pattern: r#""not_after""#,
        because: "A manifest is a grant of permission with an end. A quickstart that omitted \
                  the expiry would teach the one field that limits the blast radius as \
                  optional -- and it is not: a document without it does not load.",
    },
    Claim {
        path: README,
        criterion: "AC-7.19",
        requirement: "the quickstart shows what happens when the manifest step is skipped",
        pattern: r"(?i)required arguments were not provided:\s*--scope",
        because: "Showing the refusal is what makes the requirement credible to a reader who \
                  has not run it. This is real output, not a paraphrase.",
    },
    // --- AC-7.20: the design paper --------------------------------------
    Claim {
        path: DESIGN_PAPER,
        criterion: "AC-7.20",
        requirement: "a limitations section exists",
        pattern: r"(?i)#+ [\d. ]*Limitations",
        because: "A design paper that argues a thesis and lists no limitations is an \
                  advertisement.",
    },
    Claim {
        path: DESIGN_PAPER,
        criterion: "AC-7.20",
        requirement: "threats to validity are stated, not only limitations",
        pattern: r"(?i)threats to validity",
        because: "The measurements are this project's own benchmark of its own competitors. \
                  What defends that is not a promise -- it is naming, in the document, every \
                  reason the numbers might be wrong.",
    },
    Claim {
        path: DESIGN_PAPER,
        criterion: "AC-7.20",
        requirement: "a clean-room attestation exists",
        pattern: r"(?i)#+ [\d. ]*Clean-room attestation",
        because: "The Global Constraint makes clean-room a legal requirement, not a style \
                  preference. An attestation is where the project states it in a form someone \
                  can hold it to.",
    },
    Claim {
        path: DESIGN_PAPER,
        criterion: "AC-7.20",
        requirement: "the attestation admits Nmap is installed here and was run, as a benchmark \
                      subject",
        pattern: r"(?i)Nmap is installed on the machine this project was developed on, and it was run here",
        because: "The true statement is more complicated than 'we never touched it', and the \
                  more complicated one is the only one that survives someone who looks at \
                  bench/compare.sh. An attestation that were caught omitting this would \
                  discredit every other line of it.",
    },
    Claim {
        path: DESIGN_PAPER,
        criterion: "AC-7.20",
        requirement: "the attestation states precisely that the data files were not read",
        pattern: r"(?i)Their presence on a disk is not the boundary; opening them is, and they were not opened",
        because: "Installing Nmap necessarily puts nmap-service-probes on the disk. Which side \
                  of the line that falls on is exactly what a reader wants to know, and \
                  'we did not derive from Nmap' does not answer it.",
    },
    // --- AC-7.21: the Windows position ----------------------------------
    Claim {
        path: PLATFORM,
        criterion: "AC-7.21",
        requirement: "the Windows position is stated",
        pattern: r"(?i)Windows is out of scope for v0\.1",
        because: "Stated once, plainly, so nobody has to infer it from an absence.",
    },
    Claim {
        path: PLATFORM,
        criterion: "AC-7.21",
        requirement: "the reason given is a license, and Npcap is named",
        pattern: r"(?i)Npcap is distributed under the Npcap License",
        because: "The reason is a licensing constraint and not a technical judgement, and a \
                  document that says 'Windows is unsupported' without saying which license and \
                  why invites the reader to supply their own explanation.",
    },
    Claim {
        path: PLATFORM,
        criterion: "AC-7.21",
        requirement: "the incompatibility is with THIS project's redistribution model",
        pattern: r"(?i)incompatible with \*this\* project's redistribution model",
        because: "The honest form of the claim is symmetric: those are the terms its authors \
                  chose, and they do not fit what this project wants to be. Anything stronger \
                  would be a claim about the other project's merit, which the positioning \
                  rules forbid and which is weaker as an argument anyway.",
    },
    Claim {
        path: PLATFORM,
        criterion: "AC-7.21",
        requirement: "the document says in as many words that this is not a criticism",
        pattern: r"(?i)not a statement that Npcap is a bad piece of software",
        because: "AC-7.21 requires the position stated factually rather than as a slight. \
                  Leaving that to tone leaves it to the reader; saying it leaves nothing to \
                  infer.",
    },
    // --- the threat model (plan Step 4; no numbered criterion) -----------
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "what bathy defends against is stated",
        pattern: r"(?i)#+ [\d. ]*What bathy defends against",
        because: "The plan names three: a hostile response from a scanned endpoint, a confused \
                  or adversarial calling agent, and an over-broad scope manifest.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "what bathy does NOT defend against is stated",
        pattern: r"(?i)#+ [\d. ]*What bathy does not defend against",
        because: "A threat model that lists only wins is marketing. The plan names a \
                  compromised host running `packetd` and a malicious operator with legitimate \
                  scope; both are here, and so is everything else found while writing it.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "the trust boundaries are stated -- who is trusted, and how much",
        pattern: r"(?i)Who is trusted, and how much",
        because: "'What it defends against' is meaningless without 'from whom'. The calling \
                  agent is trusted to ask and not to authorize, and that one distinction is \
                  the whole shape of the MCP surface.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "the requestState blob is named as untrusted input on the retry",
        pattern: r"(?i)`requestState` blob round-trips through the client",
        because: "It originated here, which is exactly what makes it easy to treat as trusted. \
                  On the way back it is a caller-controlled string, and naming that is what \
                  makes the four properties below it read as necessary rather than as belt and \
                  braces.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "the approval token is described as an authorization boundary",
        pattern: r"(?i)The approval token is an authorization boundary",
        because: "A forgeable approval blob is a scope bypass: a caller hands back something \
                  claiming a human approved a scan no human saw. It is the same class of \
                  defect as an unconsulted scope check and belongs in the threat model rather \
                  than only in a module doc.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "the two-layer scope enforcement is described",
        pattern: r"(?i)two layers, and the second is not bypassable by an adapter",
        because: "The layers are not redundant and the difference is the whole point: the \
                  adapter's check is bypassable by a library caller, and the scheduler's is on \
                  the path packets actually leave by.",
    },
    Claim {
        path: THREAT_MODEL,
        criterion: "Task 4 Step 4",
        requirement: "the reason the LLM is kept off the packet path is stated",
        pattern: r"(?i)There is no language model anywhere on the packet path",
        because: "It is the project's single most important structural property and the one a \
                  reader is most likely to assume the opposite of, given the words \
                  'agent-native' on the first line of the README.",
    },
    // --- AC-7.22: evasion and anonymization as explicit non-goals ---------
    //
    // The code already commits to this: `USER_AGENT` in `probes/http.rs` and
    // `EHLO bathy.invalid` in `probes/smtp.rs` are there so a scanned party
    // can attribute the traffic, and `probes/http.rs`'s own comment points at
    // this file for the reason. A policy that did not match them would be the
    // README-versus-code divergence this project has three recorded instances
    // of, one document further out.
    Claim {
        path: SECURITY,
        criterion: "AC-7.22",
        requirement: "evasion and anonymization are named as non-goals, in a section of their own",
        pattern: r"(?i)#+ Non-goals: evasion and anonymization",
        because: "A non-goal mentioned in passing is a non-goal a feature request argues with. \
                  This one is a heading, so it can be linked to and closed against -- which is \
                  exactly what `.github/ISSUE_TEMPLATE/config.yml` does with it.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.22",
        requirement: "the non-goal is stated as permanent AND as grounds for declining requests",
        pattern: r"(?i)permanent non-goals of this project\. Feature requests for them will be declined",
        because: "AC-7.22 has two halves and the second is the one that does work. 'Not planned' \
                  reads as a backlog item; 'will be declined' is a decision, and it is the \
                  sentence a maintainer can point at without re-litigating it every time.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.22",
        requirement: "the identifying User-Agent and EHLO are described as mechanisms, matching \
                      what the probes actually send",
        pattern: r"(?i)User-Agent: bathy/<version>.{0,400}EHLO bathy\.invalid",
        because: "This project ships an identifying User-Agent and `EHLO bathy.invalid` ON \
                  PURPOSE, and `probes/http.rs` cites this file as the reason. If the policy \
                  stopped naming them, the code's justification would point at a document that \
                  no longer makes it -- the same stale-forward-reference defect this task found \
                  in the threat model's own Section 5.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.22",
        requirement: "the adjacent things NOT covered by the non-goal are listed",
        pattern: r"(?i)Adjacent things that are \*not\* covered by this non-goal",
        because: "A rule that swallows its neighbouring cases is a rule people route around. \
                  Rate limiting, a smaller port set and disabling service identification are all \
                  supported, and a reader who cannot tell them apart from evasion will either \
                  ask for them apologetically or assume they are gone.",
    },
    // --- AC-7.24: the disclosure contact and the response time ------------
    Claim {
        path: SECURITY,
        criterion: "AC-7.24",
        requirement: "a disclosure channel is published",
        pattern: r"(?i)Report privately through GitHub Security Advisories",
        because: "AC-7.24's first half. A security policy with no channel is a security policy \
                  that routes vulnerabilities into public issues.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.24",
        requirement: "a fallback exists for when private reporting is unavailable",
        pattern: r"(?i)security report, please open a private advisory",
        because: "Private vulnerability reporting can be switched off, and a fork does not \
                  inherit it. A single-channel policy whose channel is missing is worse than \
                  none, because the reporter concludes there is nowhere to go.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.24",
        requirement: "an acknowledgement window is committed to, in a number of days",
        pattern: r"(?i)Acknowledgement that the report was received and read \| \*\*3 business days\*\*",
        because: "AC-7.24's second half is a response-time EXPECTATION, which means a number. \
                  'We aim to respond promptly' is not one, and a reporter who has heard nothing \
                  cannot tell whether to bump it or give up.",
    },
    Claim {
        path: SECURITY,
        criterion: "AC-7.24",
        requirement: "the authorized-use statement is present, in as many words",
        pattern: r"(?i)\*\*bathy is for scanning networks you are authorized to scan\.\*\*",
        because: "The overview's Pre-Publication Gates require `SECURITY.md` to carry an \
                  explicit authorized-use statement, not only a disclosure path. \
                  `publish-check` asserts the same sentence independently, because a \
                  publication gate must not depend on someone having remembered to run \
                  `check-docs` first.",
    },
    // --- AC-7.23: the clean-room rule, stated for contributors ------------
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "the clean-room rule is stated as an instruction to contributors, naming \
                      the artefact kinds",
        pattern: r"(?i)\*\*Do not submit code, probe strings, fingerprint data, port lists, or interpretation rules derived from Nmap",
        because: "AC-7.23 is the rule stated FOR CONTRIBUTORS. The design paper's attestation is \
                  about what this project did; this is about what an incoming pull request may \
                  contain, and they are different sentences with different audiences.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "the rule extends beyond Nmap to any incompatibly licensed project",
        pattern: r"(?i)any other project whose licence is incompatible with Apache-2\.0 OR MIT",
        because: "The Global Constraint is about licence compatibility, not about one project. A \
                  rule naming only Nmap invites a contributor to derive from the next scanner \
                  along and be technically compliant.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "deriving from another tool's OUTPUT is named as derivation",
        pattern: r"(?i)Do not tune a rule from another scanner's output",
        because: "This is the hole a copy-nothing rule leaves open, and it is the one a \
                  well-intentioned contributor falls into: no file is copied, and the \
                  fingerprint is still derived. Naming it is what makes the boundary usable.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "a source is required for every new interpretation rule",
        pattern: r"(?i)#+ [\d. ]*Every interpretation rule cites a source, and the citation must be checkable",
        because: "AC-7.23's second half. The registry's `source` field and \
                  `every_rule_documents_its_non_nmap_source` already force a citation to EXIST; \
                  nothing in the tree can force it to be true, so the policy has to.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "the citation is required to be checkable against a named artefact -- RFC \
                      section, vendor section, or a committed capture",
        pattern: r"(?i)One of exactly three kinds of source, and nothing else",
        because: "This repository shipped TWO fabricated RFC quotations and a citation to a \
                  PostgreSQL section that does not exist. In each case a citation was present. \
                  'Cite something' was therefore not a strong enough rule, and what closes the \
                  gap is saying what the citation must be checkable AGAINST: a section number \
                  that exists, verbatim text a reviewer can search for, or bytes committed to \
                  `testdata/captures/`.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "quotations are required to be verbatim, and the reviewer's check is \
                      described",
        pattern: r"(?i)the quotation must be \*\*verbatim\*\* from that section",
        because: "The specific failure was a plausible paraphrase inside quotation marks, twice. \
                  Requiring verbatim text is what makes the reviewer's check mechanical: open \
                  the section, search for the string, and reject if it is absent.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.23",
        requirement: "a wrong citation withdraws the rule rather than editing the comment",
        pattern: r"(?i)a rule justified by a citation that was wrong was never justified",
        because: "Without this, the remedy for a fabricated citation is to reword the comment, \
                  which leaves the rule in the tree with no derivation at all. That is the \
                  outcome the two historical fabrications actually produced until they were \
                  swept.",
    },
    Claim {
        path: CONTRIBUTING,
        criterion: "AC-7.17",
        requirement: "the positioning rule binds contributors too",
        pattern: r"(?i)#+ [\d. ]*Compare tools, never people",
        because: "AC-7.17 is enforced over the tree by `check-phrases`, which catches a name \
                  after it is written. This is the sentence that tells a contributor before \
                  they write it, and it is the one that covers issues and pull requests, which \
                  no checker can see.",
    },
    // --- the code of conduct (plan Task 5 Step 3; no numbered criterion) ---
    Claim {
        path: CONDUCT,
        criterion: "Task 5 Step 3",
        requirement: "a reporting route that does not require writing the details in public",
        pattern: r"(?i)conduct report, please contact me privately",
        because: "A code of conduct whose only channel is a public issue asks a reporter to \
                  describe what happened to them in front of everyone. The specific words are \
                  pinned because the instruction is 'post exactly this and nothing else', and a \
                  reworded version is a different instruction.",
    },
    Claim {
        path: CONDUCT,
        criterion: "Task 5 Step 3",
        requirement: "the scanner-specific rule about a third party's hosts",
        pattern: r"(?i)do not post scan results identifying a third party's hosts",
        because: "This is the one clause a generic code of conduct does not have and this \
                  project needs: issues are public, and a pasted scan result is somebody else's \
                  network on a public page.",
    },
    Claim {
        path: CONDUCT,
        criterion: "Task 5 Step 3",
        requirement: "the adaptation is declared rather than passed off as the original text",
        pattern: r"(?i)It is an adaptation and not a copy",
        because: "The Contributor Covenant is CC BY 4.0 and this document is a rewrite, not a \
                  copy. A project whose CONTRIBUTING.md rejects paraphrase-inside-quotation-marks \
                  cannot present its own paraphrase as somebody else's text.",
    },
    // --- the issue templates (AC-7.22's operational half) ------------------
    Claim {
        path: FEATURE_TEMPLATE,
        criterion: "AC-7.22",
        requirement: "the feature template declines evasion and anonymization up front",
        pattern: r"(?i)Detection evasion and anonymization\.",
        because: "AC-7.22 says requests for them will be declined. The place that is cheapest to \
                  honour is before the request is written, and the template is the only document \
                  a requester is guaranteed to see.",
    },
    Claim {
        path: FEATURE_TEMPLATE,
        criterion: "AC-7.22",
        requirement: "the template also says what is NOT covered by the non-goal",
        pattern: r"(?i)rate limiting, connect timeouts, concurrency ceilings, smaller port sets, and disabling service identification entirely are all supported",
        because: "Same reason as `SECURITY.md`'s list, one step earlier: a requester who cannot \
                  tell rate limiting apart from evasion will not ask for it.",
    },
    Claim {
        path: RULE_TEMPLATE,
        criterion: "AC-7.23",
        requirement: "the rule template demands the citation, verbatim, with the reviewer's check \
                      stated",
        pattern: r"(?i)a reviewer will open your citation and\s+search for your string",
        because: "AC-7.23's requirement has to reach the point where a rule is proposed. The \
                  template is where a contributor decides how much care the citation needs, and \
                  telling them exactly what will be done with it is what makes the answer 'a \
                  lot'.",
    },
    Claim {
        path: RULE_TEMPLATE,
        criterion: "AC-7.23",
        requirement: "a clean-room confirmation is required on the form",
        pattern: r"(?i)and not from Nmap,\s+`nmap-service-probes`",
        because: "A checkbox is not a licence audit and this does not pretend to be one. It is \
                  the point at which a contributor who HAS looked at those files has to notice \
                  that they have, which is the only realistic control available here.",
    },
];

/// Every claim that is missing, as a message that names the criterion, the
/// file, what was required and why.
///
/// Pure: `documents` supplies each path's text, so every rule below is
/// testable against synthetic input, and a test can delete one sentence
/// without touching a file on disk.
pub fn violations(documents: &[(&str, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for claim in CLAIMS {
        let Some((_, text)) = documents.iter().find(|(p, _)| *p == claim.path) else {
            out.push(format!(
                "{}: {} is required by {} and was not read at all.",
                claim.path, claim.requirement, claim.criterion,
            ));
            continue;
        };
        let re = Regex::new(claim.pattern).expect("checker pattern must compile");
        if !re.is_match(&flatten(text)) {
            out.push(format!(
                "{}: {} ({}).\n  pattern `{}` matched nothing.\n  why this is required: {}\n  \
                 Either the sentence was deleted -- then the criterion is no longer met and the \
                 fix is the document, not this file -- or it was reworded, in which case the \
                 pattern must follow it.",
                claim.path, claim.requirement, claim.criterion, claim.pattern, claim.because,
            ));
        }
    }
    out
}

/// Collapse a document into one line so patterns are independent of hard
/// wrapping, which is how these files are written and how they will be
/// rewrapped. Same reasoning, and same treatment of blockquote markers, as
/// [`crate::readme`]'s.
fn flatten(text: &str) -> String {
    let mut joined = String::new();
    for line in text.lines() {
        let mut rest = line.trim_start();
        while let Some(stripped) = rest.strip_prefix('>') {
            rest = stripped.trim_start();
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(rest.trim_end());
    }
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Where each `## ` heading starts, in order, as `(line index, title)`.
///
/// Section *position* is a claim in its own right -- AC-7.18 says "above the
/// fold", which is a statement about order rather than about presence -- and
/// order is the one thing [`flatten`] destroys.
fn top_level_headings(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, line)| {
            line.strip_prefix("## ")
                .map(|title| (i, title.trim().to_string()))
        })
        .collect()
}

/// AC-7.18's *position* half: authorized use must be the first section of the
/// README and must begin near the top of the file.
///
/// "Above the fold" needs an operational meaning or it means nothing. Two
/// conditions, both of which a reader would notice being broken:
///
/// 1. It is the **first** `## ` section. Not merely present, not merely
///    before the quickstart -- first. Anything ahead of it is something this
///    project decided a reader should see before being told what the tool is
///    for.
/// 2. It starts within [`FOLD_LINES`] of the top. A first section is still
///    below the fold if two screens of prose precede the first heading.
const FOLD_LINES: usize = 40;

pub fn fold_violations(readme: &str) -> Vec<String> {
    let headings = top_level_headings(readme);
    let mut out = Vec::new();
    let Some((line, title)) = headings.first() else {
        out.push(format!(
            "{README}: no `## ` section at all, so AC-7.18's authorized-use statement cannot be \
             above the fold."
        ));
        return out;
    };
    if !title.eq_ignore_ascii_case("Authorized use") {
        out.push(format!(
            "{README}: AC-7.18 requires the authorized-use statement above the fold, and the \
             first section is `## {title}` (line {}). Being present somewhere is not the \
             criterion: a reader who stops after the first screen must have read it.",
            line + 1,
        ));
    }
    if *line >= FOLD_LINES {
        out.push(format!(
            "{README}: AC-7.18's authorized-use statement starts at line {}, past the {FOLD_LINES}\
             -line fold. A first section is still below the fold if enough prose precedes it.",
            line + 1,
        ));
    }
    out
}

/// Every packet-emitting `bathy` invocation inside the quickstart must pass
/// `--scope`.
///
/// AC-7.19's other half, and the one a "does the manifest step exist" check
/// cannot see: a quickstart that writes a manifest and then shows a command
/// that does not use it teaches that the manifest is decorative. The two
/// deliberate exceptions are the two commands the quickstart shows *failing*,
/// which is how it demonstrates the requirement.
pub fn quickstart_violations(readme: &str) -> Vec<String> {
    let Some(section) = section_of(readme, "60-second quickstart") else {
        // The presence of the section is [`CLAIMS`]' business; this function
        // reports nothing rather than reporting it twice.
        return Vec::new();
    };
    let emits =
        Regex::new(r"bathy(?: --\S+(?: \S+)?)* (?:scan (?:preview|start|resume)|scope validate)")
            .expect("checker pattern must compile");
    let mut out = Vec::new();
    for (index, line) in section.lines().enumerate() {
        if !emits.is_match(line) {
            continue;
        }
        // The whole command, which the file wraps with a trailing backslash.
        let mut whole = line.to_string();
        let mut rest = section.lines().skip(index + 1);
        while whole.trim_end().ends_with('\\') {
            let Some(next) = rest.next() else { break };
            whole.push_str(next);
        }
        if whole.contains("--scope") {
            continue;
        }
        // The one legitimate shape: a command shown in order to demonstrate
        // that it is refused. It is recognised by what follows it, not by an
        // allow-list of line numbers, so moving it does not break the check.
        let after: String = section
            .lines()
            .skip(index + 1)
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");
        if after.contains("required arguments were not provided") {
            continue;
        }
        out.push(format!(
            "{README}: the quickstart runs `{}` with no `--scope` (AC-7.19).\n  \
             Every packet-emitting command in the quickstart must carry the manifest, or the \
             quickstart teaches that it is optional. The one exception is a command shown in \
             order to be refused, and that one is followed by its own refusal.",
            whole.trim(),
        ));
    }
    out
}

/// The text under `## <title>`, up to the next `## `.
fn section_of(text: &str, title: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.starts_with("## ") && l[3..].trim().eq_ignore_ascii_case(title))?;
    let end = lines
        .iter()
        .skip(start + 1)
        .position(|l| l.starts_with("## "))
        .map_or(lines.len(), |offset| start + 1 + offset);
    Some(lines[start..end].join("\n"))
}

pub fn check_docs() -> Fallible<()> {
    let root = Path::new(".");
    let mut documents: Vec<(&str, String)> = Vec::new();
    let mut missing = Vec::new();
    for path in DOCUMENTS.iter().copied() {
        match std::fs::read_to_string(root.join(path)) {
            Ok(text) => documents.push((path, text)),
            Err(e) => missing.push(format!("{path}: {e}")),
        }
    }

    let mut found = missing;
    found.extend(violations(&documents));
    if let Some((_, readme)) = documents.iter().find(|(p, _)| *p == README) {
        found.extend(fold_violations(readme));
        found.extend(quickstart_violations(readme));
    }

    if found.is_empty() {
        println!(
            "check-docs: ok ({} claim(s) over {} document(s))",
            CLAIMS.len(),
            documents.len()
        );
        return Ok(());
    }
    for v in &found {
        eprintln!("check-docs: {v}");
    }
    Err(format!("{} documentation claim(s) not met", found.len()).into())
}

// ---------------------------------------------------------------------------
// NOT MECHANICALLY CHECKED -- written out deliberately, as `readme.rs` does.
//
//   - **Whether any of it is true.** This module asserts that a document says
//     a thing. That the TLS gap description matches what `detect_service`
//     actually does, that the Npcap summary matches Npcap's current terms,
//     that the threat model's list of what is not defended is complete --
//     none of that is readable from here. The benchmark numbers are the one
//     part with a mechanical guard, and it is `check-bench`, not this.
//   - **Completeness of the limitations sections.** A limitation nobody wrote
//     down is invisible. `CLAIMS` is a register of the ones the plan names
//     and the ones this round found; a new one omitted tomorrow trips
//     nothing. This is the same honest limit `FUZZ_SURFACES` records.
//   - **The quickstart's output.** The transcript was produced by executing
//     the quickstart from a clean state, and the scan id, plan hash, evidence
//     digest and timestamps in it are that run's. Nothing re-executes it, so
//     a behaviour change that alters the output leaves the transcript stale
//     and this check green. Re-run it at every milestone exit; it takes a
//     minute and it is the single most likely wrong thing in the file.
//   - **Every document not in the list above.** `docs/benchmarks.md` is
//     `check-bench`'s; `docs/protocol-notes.md`, `docs/event-log-
//     compatibility.md`, `lab/README.md` and `fuzz/README.md` have no
//     structural checker at all.
//   - **Prose quality, tone, and whether the positioning argument lands.**
//     `check-phrases` catches a named individual and a forbidden phrase. It
//     cannot catch a paragraph that is technically compliant and still reads
//     as a swipe at another project.
//   - **Whether the disclosure channel actually works.** AC-7.24 is discharged
//     here by the presence of a channel and a number of days. Whether GitHub's
//     private vulnerability reporting is switched on for the repository, and
//     whether anyone is watching it, is a setting on a website and a promise
//     about a human being. `publish-check` prints both in its manual-gate
//     block for exactly that reason.
//   - **Whether the response times are met.** A committed acknowledgement
//     window is a claim about the future, and no checker reads the future. It
//     is here because an uncheckable commitment that someone can hold this
//     project to is worth more than a checkable evasion.
//   - **Whether a contributor's citation is true.** CONTRIBUTING.md's rule is
//     that an RFC section must exist and a quotation must be verbatim. Nothing
//     in this repository opens an RFC. The two fabricated quotations this
//     project has shipped were both found by a person reading the source
//     document, and that is still the only thing that finds them --  which is
//     why the rule is written as an instruction to the *reviewer* ("open the
//     link and search for the string") rather than as a property of the tree.
//   - **The `.github/ISSUE_TEMPLATE/` directory beyond the two templates named
//     above.** `bug_report.md` and `config.yml` carry no acceptance criterion,
//     so nothing here pins their contents; a deleted `config.yml` would
//     silently re-enable blank issues and no check would notice.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A claim over a document [`check_docs`] never reads is a claim that can
    /// never fire, and it looks exactly like one that passes.
    ///
    /// This is the defect `readme.rs`'s `ABSENCE_CLAIMS` shipped in another
    /// shape: a register entry whose falsifier was a path that could not
    /// exist, so the check stayed green through three tasks that made the
    /// claim false. Here the same mistake is one typo away -- a `Claim` naming
    /// `docs/SECURITY.md` (which is where the overview's File Structure puts
    /// it, and it is not where it lives) would be reported as "was not read at
    /// all" rather than silently, but only because `violations` says so; this
    /// test is what makes the register itself well-formed.
    #[test]
    fn every_claim_names_a_document_that_check_docs_actually_reads() {
        for claim in CLAIMS {
            assert!(
                DOCUMENTS.contains(&claim.path),
                "{} names `{}`, which is not in DOCUMENTS, so check_docs never reads it",
                claim.criterion,
                claim.path,
            );
        }
        // And the other direction: a document read but never claimed against
        // is a file this module pretends to cover. Not fatal -- but it must be
        // deliberate, so it is asserted rather than left to drift.
        for path in DOCUMENTS {
            assert!(
                CLAIMS.iter().any(|c| c.path == *path),
                "`{path}` is read by check_docs and no claim covers it",
            );
        }
    }

    /// Every document in the register exists in the tree under exactly the
    /// path the register spells.
    ///
    /// `check_docs` reports a missing file, so this is not the only guard --
    /// but it fails in one second with the path, rather than in the middle of
    /// a gate run, and it is the test that catches `SECURITY.md` versus
    /// `docs/SECURITY.md` before a reviewer does.
    #[test]
    fn every_registered_document_exists_at_that_exact_path() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for path in DOCUMENTS {
            assert!(
                root.join(path).is_file(),
                "DOCUMENTS names `{path}`, which is not a file in the repository",
            );
        }
    }

    /// The repository's own documents must satisfy every claim. This is the
    /// test that ties `CLAIMS` to the tree rather than to a fixture, and the
    /// one that goes red the day a section is deleted.
    #[test]
    fn the_repositorys_own_documents_meet_every_claim() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let documents: Vec<(&str, String)> = DOCUMENTS
            .iter()
            .copied()
            .map(|p| {
                (
                    p,
                    std::fs::read_to_string(root.join(p))
                        .unwrap_or_else(|e| panic!("reading {p}: {e}")),
                )
            })
            .collect();
        let found = violations(&documents);
        assert!(found.is_empty(), "unmet claim(s):\n{}", found.join("\n\n"));
    }

    #[test]
    fn the_repositorys_readme_puts_authorized_use_above_the_fold() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let readme = std::fs::read_to_string(root.join(README)).expect("README.md");
        let found = fold_violations(&readme);
        assert!(found.is_empty(), "{}", found.join("\n"));
    }

    #[test]
    fn the_repositorys_quickstart_passes_the_manifest_to_every_command() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let readme = std::fs::read_to_string(root.join(README)).expect("README.md");
        let found = quickstart_violations(&readme);
        assert!(found.is_empty(), "{}", found.join("\n"));
    }

    /// Every claim must be able to fail. A pattern that matches the empty
    /// document is a claim that proves nothing, and it would look exactly
    /// like a passing one.
    #[test]
    fn no_claim_is_satisfied_by_an_empty_document() {
        let documents: Vec<(&str, String)> = DOCUMENTS
            .iter()
            .copied()
            .map(|p| (p, String::new()))
            .collect();
        let found = violations(&documents);
        assert_eq!(
            found.len(),
            CLAIMS.len(),
            "every claim must fail over an empty tree; {} of {} did",
            found.len(),
            CLAIMS.len()
        );
    }

    /// And each one must fail *individually*, with its criterion named -- the
    /// mutation form. Deleting one required sentence from an otherwise
    /// correct document must produce exactly one failure, and that failure
    /// must say which criterion is now unmet.
    #[test]
    fn deleting_any_one_required_sentence_fails_that_claim_and_names_its_criterion() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        // Read and flatten once. Both are pure, and doing them inside the
        // loop made this test read the same four files 116 times.
        let originals: Vec<(&str, String)> = DOCUMENTS
            .iter()
            .copied()
            .map(|p| {
                (
                    p,
                    flatten(
                        &std::fs::read_to_string(root.join(p))
                            .unwrap_or_else(|e| panic!("reading {p}: {e}")),
                    ),
                )
            })
            .collect();
        for claim in CLAIMS {
            let mut documents = originals.clone();

            // Blank out exactly what this claim matches, leaving every other
            // sentence in place. The edit is made on the *flattened* text --
            // which is what `violations` reads, and `flatten` is idempotent --
            // because the required sentences are hard-wrapped and a
            // line-oriented deletion cannot remove one that straddles a line
            // break. Two of them do.
            let re = Regex::new(claim.pattern).expect("pattern must compile");
            for (path, text) in &mut documents {
                if *path != claim.path {
                    continue;
                }
                let flat = text.clone();
                // `replace_all`, not `find`: two of these sentences are
                // deliberately stated twice -- once in the limitations
                // section and once in the summary that points at it -- and
                // removing only the first leaves the claim satisfied by the
                // second. The property under test is that the *statement*
                // going away is caught, not that one copy of it is.
                let mutated = re.replace_all(&flat, "").into_owned();
                assert!(
                    mutated.len() < flat.len(),
                    "fixture sanity: {} does not satisfy {:?}",
                    claim.path,
                    claim.requirement
                );
                *text = mutated;
            }

            let found = violations(&documents);
            assert!(
                found.iter().any(|v| v.contains(claim.requirement)),
                "removing the sentence for {:?} ({}) produced no failure naming it:\n{}",
                claim.requirement,
                claim.criterion,
                found.join("\n"),
            );
            assert!(
                found.iter().any(|v| v.contains(claim.criterion)),
                "the failure for {:?} must name its criterion",
                claim.requirement,
            );
        }
    }

    /// AC-7.18 is about *position*, and the mutation that matters is not
    /// deleting the section -- it is moving it down, which is a one-line edit
    /// that leaves every presence check green.
    #[test]
    fn moving_authorized_use_below_another_section_fails() {
        let readme =
            "# bathy\n\nIntro.\n\n## What it is\n\nProse.\n\n## Authorized use\n\nDon't.\n";
        let found = fold_violations(readme);
        assert!(
            found.iter().any(|v| v.contains("What it is")),
            "the failure must name the section that got in front of it: {found:?}"
        );
    }

    #[test]
    fn a_first_section_pushed_past_the_fold_by_prose_fails() {
        let mut readme = String::from("# bathy\n\n");
        for _ in 0..FOLD_LINES {
            readme.push_str("Filler.\n");
        }
        readme.push_str("\n## Authorized use\n\nDon't.\n");
        let found = fold_violations(&readme);
        assert!(
            found.iter().any(|v| v.contains("past the")),
            "a section below two screens of prose is not above the fold: {found:?}"
        );
    }

    #[test]
    fn authorized_use_first_and_near_the_top_is_not_a_violation() {
        let readme = "# bathy\n\nTwo sentences.\n\n## Authorized use\n\nDon't.\n\n## Quickstart\n";
        assert!(fold_violations(readme).is_empty());
    }

    /// The AC-7.19 mutation: a quickstart command that stops passing the
    /// manifest. This is the edit that makes the manifest look decorative,
    /// and no presence check sees it.
    #[test]
    fn a_quickstart_command_without_the_manifest_is_caught() {
        let readme = "\
## 60-second quickstart

```
cat > quickstart-scope.json <<EOF
EOF
$ bathy --state-dir ./s scan start --idempotency-key k --targets 10.0.0.1 --ports 80
```

## Next
";
        let found = quickstart_violations(readme);
        assert_eq!(found.len(), 1, "got: {found:?}");
        assert!(found[0].contains("AC-7.19"), "{}", found[0]);
    }

    /// And the shape that must NOT be flagged: the command the quickstart
    /// shows in order to demonstrate the refusal.
    #[test]
    fn the_command_shown_in_order_to_be_refused_is_not_a_violation() {
        let readme = "\
## 60-second quickstart

```
$ bathy scan start --idempotency-key x --targets 10.0.0.1 --ports 80
error: the following required arguments were not provided:
  --scope <PATH>
```

## Next
";
        assert!(quickstart_violations(readme).is_empty());
    }

    /// A wrapped command must be read whole. Without the continuation
    /// handling, the first line of `scan start \` carries no `--scope` and
    /// the check cries wolf on the correct file -- and a check that cries
    /// wolf is one someone deletes.
    #[test]
    fn a_command_wrapped_over_lines_is_read_as_one_command() {
        let readme = "\
## 60-second quickstart

```
$ bathy --state-dir ./s scan start \\
    --scope quickstart-scope.json --idempotency-key k \\
    --targets 10.0.0.1 --ports 80
```

## Next
";
        assert!(quickstart_violations(readme).is_empty());
    }

    #[test]
    fn every_claim_has_a_pattern_that_compiles_and_a_stated_reason() {
        for claim in CLAIMS {
            Regex::new(claim.pattern)
                .unwrap_or_else(|e| panic!("{}: invalid pattern: {e}", claim.requirement));
            assert!(
                !claim.because.trim().is_empty(),
                "claim {:?} requires something with no stated reason",
                claim.requirement
            );
            assert!(
                !claim.criterion.trim().is_empty(),
                "claim {:?} names no criterion",
                claim.requirement
            );
        }
    }
}
