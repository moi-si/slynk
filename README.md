*Forked from [TlsFragment](https://github.com/maoist2009/TlsFragment)*
# Slynk
Slynk is an asyncio-based local relay server that can protect HTTPS connections. *Note: It may use more memory than TlsFragment.*
## How to start
1. Make sure Python 3.8+ or newer installed.
2. Clone this repository:

   ```
   git clone https://github.com/moi-si/Slynk
   cd Slynk
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
I'm too lazy to write documentation. Please read the source code or check [DeepWiki](https://deepwiki.com/moi-si/slynk) for auto-generated docs (updated every 7 days).
## To-do
- [x] TLSfrag
- [x] FAKEdesync
- [x] SOCKS5
- [x] PAC
- [x] BySNIfirst
- [x] DNS over UDP/TCP
