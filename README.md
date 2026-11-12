# OpenDrop (working name)

OpenDrop is an **early-stage** open-source project aiming to provide a secure,
native-feeling, AirDrop-class local sharing experience across **Linux, Windows,
and Android**. All three platforms are first-class development and release
targets.

**Development status:** This repository contains experimental production
foundations and native platform integration work. It is **not yet a finished
or security-audited file-sharing application**. A successfully built Android
debug APK or compiled Linux component is not proof of end-to-end production
sharing. Windows packaging and native OS activation still require validation.

## Scope and compatibility

Our goal is a fast, intuitive, private local sharing experience across the
three target platforms. Automatic nearby discovery, explicit consent, verified
device trust, reliable transfers and native OS integration are goals that
must be established by real platform testing before being advertised as
working features.

**Direct interoperability with Apple's proprietary AirDrop protocol is a
separate research objective, not a supported capability of this project.**

## Name and attribution

**OpenDrop is a provisional working name.** This project at
[Suraj-H675/OpenDrop](https://github.com/Suraj-H675/OpenDrop)
is independent of the earlier
[SEEMOO Lab / Open Wireless Link OpenDrop](https://github.com/seemoo-lab/opendrop)
project, which is a different AirDrop-protocol implementation.
This project is not affiliated with, sponsored by or endorsed by the SEEMOO
Lab project or Apple Inc. No code from the SEEMOO GPL-licensed implementation
is claimed as part of this repository.

A final distribution name and any relevant trademark/brand conflicts must
be evaluated before public product launch. Product and third-party marks
remain the property of their respective owners.

## License

The original OpenDrop source code in this repository is licensed under the
**Apache License, Version 2.0**. See [LICENSE](LICENSE).

Third-party libraries and other external materials retain their own
licenses and required notices. Do not infer that a dependency's license is
changed by this repository's Apache-2.0 license.

The neutral Windows MSIX images included here are explicitly marked
**TEST ONLY**. They are packaging validation inputs, not approved product
branding or release assets.
