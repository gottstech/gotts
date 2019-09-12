# Gotts's Security Process

Gotts has a [code of conduct](CODE_OF_CONDUCT.md) and the handling of vulnerability disclosure is no exception. We are committed to conduct our security process in a professional and civil manner. Public shaming, under-reporting or misrepresentation of vulnerabilities will not be tolerated.

## Responsible Disclosure

For all security related issues, Gotts has two main point of contact:

* gotts.tech at protonmail.com
* [TBD] 

Send all communications to both parties and expect a reply within 48h.

## Vulnerability Handling

Upon reception of a vulnerability disclosure, the Gotts team will:

* Reply within a 48h window.
* Within a week, a [CVVS v3](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator) severity score should be attributed.
* Keep communicating regularly about the state of a fix, especially for High or Critical severity vulnerabilities.
* Once a fix has been identified, agree on a timeline for release and public disclosure.

Releasing a fix should include the following steps:

* Creation of a CVE number for all Medium and above severity vulnerabilities.
* Notify all package maintainers or distributors.
* Inclusion of a vulnerability explanation, the CVE and the security researcher or team who found the vulnerability in release notes and project vulnerability list (link TBD).
* Publicize the vulnerability commensurately with severity and encourage fast upgrades (possibly with additional documentation to explain who is affected, the risks and what to do about it).

_Note: Before Gotts mainnet is released, we will be taking some liberty in applying the above steps, notably in issuing a CVE and upgrades._

## Recognition and Bug Bounties

For the opensource developer who report/fix a vulnerability, Gotts team will:

* Advertising the vulnerability, the researchers, or their team on a public page linked from our website, with a links of their choosing.
* Acting as reference whenever this is needed.
* Setting up retroactive bounties whenever possible.

Before mainnet release, we will also setup a bounty program and give proper amounts rewards based on available funds and CVVS score.

## Code Reviews and Audits

While we intend to undergo more formal audits before release, continued code reviews and audits are required for security. As such, we encourage interested security researchers to:

* Review our code, even if no contributions are planned.
* Publish their findings whichever way they choose, even if no particular bug or vulnerability was found. We can all learn from new sets of eyes and benefit from increased scrutiny.
* Audit the project publicly. While we may disagree with some small points of design or trade-offs, we will always do so respectfully.

## Chain Splits

The Gotts Team runs a chain split monitoring tool at (TBD). It is encouraged to monitor it regularly and setup alerts. In case of an accidental chain split:

* Exchanges and merchants should either cease operation or extend considerably confirmation delays.
* Miners and mining pools should immediately consult with Gotts's development team on regular channels (Gotts's Gitter mainly) to diagnose the split and determine a course of events.
* In the likely event of an emergency software patch, all actors should upgrade as soon as possible.

## Useful References

* [Reducing the Risks of Catastrophic Cryptocurrency Bugs](https://medium.com/mit-media-lab-digital-currency-initiative/reducing-the-risk-of-catastrophic-cryptocurrency-bugs-dcdd493c7569)
* [Security Process for Open Source Projects](https://alexgaynor.net/2013/oct/19/security-process-open-source-projects/)
* [Choose-Your-Own-Security-Disclosure-Adventure](http://hackingdistributed.com/2018/05/30/choose-your-own-security-disclosure-adventure/)
* [CVE HOWTO](https://github.com/RedHatProductSecurity/CVE-HOWTO)
* [National Vulnerability Database](https://nvd.nist.gov/)
