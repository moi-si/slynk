*Forked from [TlsFragment](https://github.com/maoist2009/TlsFragment)*
# Slynk
[![](https://img.shields.io/github/release/moi-si/slynk.svg)](https://github.com/moi-si/slynk/releases/latest)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/moi-si/slynk)

Slynk is an asyncio-based local relay server that can protect HTTPS connections. *Note: It may use more memory than TlsFragment.*
## How to start
1. Make sure Python 3.8+ or newer installed.
2. Clone this repository:

   ```
   git clone https://github.com/moi-si/slynk
   cd slynk
   ```
3. Install the required packages for Slynk by running:

   ```
   pip install -r requirements.txt
   ```
4. Run `slynk.py` to start the relay:

   ```
   python slynk.py
   ```
## How to use
I'm too lazy to write documentation. Please read the source code or ask DeepWiki.
## To-do
- [x] TLSfrag
- [x] FAKEdesync
- [x] SOCKS5
- [x] PAC
- [x] BySNIfirst
- [x] DNS over UDP/TCP
