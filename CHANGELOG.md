# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.2.8] - 2020-09-11
### Fixed
- Fix handling of Twitter URLs with parameters

## [2.2.7] - 2020-09-10
### Fixed
- Remove newlines before checking equality

## [2.2.6] - 2020-09-10
### Fixed
- Fix handling of keys without selfCertifications

## [2.2.5] - 2020-09-06
### Changed
- Add domain to proof displays for gitea and gitlab
- Allow Mastodon backlinks to be URLs containing fingerprint

## [2.2.4] - 2020-08-31
### Fixed
- Fix var declaration

## [2.2.3] - 2020-08-31
### Fixed
- Make server verification case insensitive

## [2.2.2] - 2020-08-31
### Fixed
- Fix missing env variable

## [2.2.1] - 2020-08-30
### Added
- Add a Getting Started page
### Changed
- Update FAQ
- Migrate to different QR library

## [2.2.0] - 2020-08-24
### Added
- Add environment variable to set Onion-Location header
- Support images embedded in keys
- Support Gitea proofs
- Support GitLab proofs
- Support Twitter verification without Twitter API key
### Fixed
- Fix env template DOMAIN name
- Fix non-updating guide titles

## [2.1.1] - 2020-08-15
### Fixed
- Fix duplicate proof verifications

## [2.1.0] - 2020-08-15
### Added
- Custom XMPP vCard fetch server setting
- Custom Express port setting
- Custom domain setting
- Include Keyoxide version number in footer
### Changed
- Improve static link handling to dependencies
- Get notations from all available UIDs
- Add timeout to some fetch calls
### Fixed
- Fix hardcoded URLs

## [2.0.2] - 2020-08-13
### Fixed
- Reference to old license

## [2.0.1] - 2020-08-12
### Fixed
- Reference to old license

## [2.0.0] - 2020-08-09
### Added
- Docker containers
### Changed
- NodeJS backend
- Distinguish primary email address from additional email addresses
### Fixed
- Profile view for keys without name

## [1.0.0] - 2020-07-30
### Added
- license-check-and-add NPM tool and scripts
### Changed
- Migrated to AGPL-3.0-or-later

## [0.4.0] - 2020-07-23
### Added
- QR code for XMPP+OMEMO
### Changed
- Update design
- Update index content
- Remove dependency on external MD5 library
- Improve WKD URL generator

## [0.3.1] - 2020-07-21
### Changed
- Update openpgpjs to v4.10.7

## [0.3.0] - 2020-07-18
### Added
- dev.to identity proof
- XMPP identity proof
### Fixed
- Improve proof snippets
- Prevent null proofs from displaying

## [0.2.1] - 2020-07-16
### Fixed
- Make www optional for reddit regex

## [0.2.0] - 2020-07-16
### Added
- Discourse identity proof
- Pleroma identity proof
- New logo
### Changed
- Update openpgpjs to v4.10.6
- Update design
- New favicon
- Improve Keybase guide
### Fixed
- Remove underscores from verify and encrypt links
- Hide revoked userids
- Hide null proofs

## [0.1.0] - 2020-07-05
### Added
- Keybase keys support
- Profile URL generator utility
### Fixed
- Identity proofs case sensitivity
