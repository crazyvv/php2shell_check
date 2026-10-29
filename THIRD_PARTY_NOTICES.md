# Third-party references

The vendor fix reference data in `rules/vendor-patches.json` is adapted from
[openai/php2shell-checker](https://github.com/openai/php2shell-checker), commit
`ffcd3fc82e5b404f2a04a95b2805ca7639d530fa`, specifically its
[`phpcheck-server` instructions](https://github.com/openai/php2shell-checker/blob/ffcd3fc82e5b404f2a04a95b2805ca7639d530fa/skills/phpcheck-server/SKILL.md).
The upstream project is licensed under Apache License 2.0; a copy is provided
in [licenses/php2shell-checker-APACHE-2.0.txt](licenses/php2shell-checker-APACHE-2.0.txt).
The data has been converted into JSON and augmented with scope and provenance
fields. Referencing the project does not imply affiliation or endorsement.

The reference table is not independent verification of the linked vendor
advisories. Results explicitly preserve this distinction, as well as the
unverified status of uploaded host reports. HTTP header classification and
local evidence handling are implemented in Rust in this project.

Passive technology signature coverage in `rules/fingerprints.json` is adapted
from the detector ideas and published signatures in
[spcaeo/php2shell-check](https://github.com/spcaeo/php2shell-check), commit
`78afcd9b8d88e76549f5d2fc9d61e9f077fe081e`. The matching engine, configurable
schema, bounded evidence handling and conservative verdict integration are
implemented in Rust in this project. The upstream license and notice are
preserved in [licenses/spcaeo-php2shell-check-MIT.txt](licenses/spcaeo-php2shell-check-MIT.txt)
and [licenses/spcaeo-php2shell-check-NOTICE.txt](licenses/spcaeo-php2shell-check-NOTICE.txt).
Technology hints do not establish a runtime, ownership or patch status. This
integration does not imply affiliation or endorsement.

The defensive chain descriptions and evidence-lab design also reference the
published research in [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc),
commit `caffb96b0a165eb3796828a9a1dc7445ec7ff77d`, and the SAPI/event
classification concepts described by [murrez/php2shell](https://github.com/murrez/php2shell),
commit `7de30d56887d20e4bfc1b3f90b47f067917742c7`. Both repositories are MIT
licensed. No exploit payload, target interaction code or executable source was
copied into this project; the evidence engine and synthetic fixtures are an
independent Rust implementation.
