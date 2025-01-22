## VeriSSO Privacy-Preserving Legacy-Compatible Single Sign-On Using Verifiable Credentials and Threshold Tokens

This is the source code of the VeriSSO PoC. The project can be downloaded and tested for reproducing the execution time of the protocol functionalities evaluated in the paper.

### Test Compilation.
1. We will need an IDE with Rust toolchainbuild environment installed.
2. Clone the project and import into the IDE.
3. Build and run the project (main.rs).
4. The test program will execute the following functions and dispay the results on the console
   - `test_credential` This will test the runtime for VC issuance, VC verificaiton, SPoK creation and SPoK verification.
   - `test_credential` This will test the runtime for ID token issuance and verification.