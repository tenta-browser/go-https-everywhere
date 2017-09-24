Go HTTPS Everywhere
===================

[![GoDoc](https://godoc.org/github.com/tenta-browser/go-https-everywhere?status.svg)](https://godoc.org/github.com/tenta-browser/go-https-everywhere)

[HTTPS Everywhere](https://github.com/EFForg/https-everywhere) rewrite engine implementation in Golang.

Contains exports for both compressed ruleset construction, client-side read-only use,
and the reconstruction into memory of compressed rules, and finally the actual intended URL rewrite logic. Matching and rewrite operations
use a [regex interface bridge](https://github.com/tenta-browser/go-pcre-matcher) package, which can be implemented in the target
environment.

Currently missing the cookie secure flag feature which will be in a future iteration.

Contact: developer@tenta.io

Installation
============

1. `go get github.com/tenta-browser/go-https-everywhere`

API
===

* `Parse()`: Reads, and constructs the rulesets into memory
* `Encode()`/`Decode()`/`EncodeToPath()`: Handles encode and decode operations
* `TryRewrite()`: Searches and (if applicable) rewrites the input url according to the rewrite rules
* `ShowStats()`: Prints a line of encoding statistics

License
=======

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

For any questions, please contact developer@tenta.io

Contributing
============

We welcome contributions, feedback and plain old complaining. Feel free to open
an issue or shoot us a message to developer@tenta.io. If you'd like to contribute,
please open a pull request and send us an email to sign a contributor agreement.

About the EFF
=============

HTTPS Everywhere is a project of the Electronic Frontier Foundation. 

The Electronic Frontier Foundation is the leading nonprofit organization defending civil liberties in the digital world. Founded in 1990, EFF champions user privacy, free expression, and innovation through impact litigation, policy analysis, grassroots activism, and technology development. 

[Support the EFF and HTTPS Everywhere](https://supporters.eff.org/donate/support-https-everywhere)

About Tenta
===========

This HTTPS Everywhere Library is brought to you by Team Tenta. Tenta is your [private, encrypted browser](https://tenta.com) that protects your data instead of selling. We're building a next-generation browser that combines all the privacy tools you need, including built-in OpenVPN. Everything is encrypted by default. That means your bookmarks, saved tabs, web history, web traffic, downloaded files, IP address and DNS. A truly incognito browser that's fast and easy.
