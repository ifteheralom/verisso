# VeriSSO Privacy-Preserving Legacy-Compatible Single Sign-On Using Verifiable Credentials and Threshold Tokens

This is the source code of the VeriSSO PoC. The project can be downloaded and tested for reproducing the execution time of the protocol functionalities evaluated in the paper.

## Experiments
You can run the experiments in your local computer with docker and in CloudLab.

### Local Computer with Docker

1. Install Docker on your local machine.
2. Copy `.env.example` to `.env` and adjust the configuration as needed.
   ```bash
   cp .env.example .env
   ```
3. Build the Docker image:
   ```bash
   docker build -t as/node .
   ```
4. Run the docker compose:
   ```bash
   docker-compose up
   ```

### CloudLab
First, install the requirements for python environment:
```bash
pip install -r requirements.txt
```

1. Initiate the CloudLab environment.
```bash
USER=<your_username> PWORD=<your_password> CERT=<your_cert_file> python exp/main.py -e <your_experiment_name> -p <experiment_profile_name> -j <your_project_name> -c init
```

2. Copy the code to individual CloudLab nodes.
```bash
USER=<your_username> PWORD=<your_password> CERT=<your_cert_file> python exp/main.py -e <your_experiment_name> -p <experiment_profile_name> -j <your_project_name> -c copy
```

3. Setup each CloudLab node.
```bash
USER=<your_username> PWORD=<your_password> CERT=<your_cert_file> python exp/main.py -e <your_experiment_name> -p <experiment_profile_name> -j <your_project_name> -c setup
```

4. Run the experiments.
```bash
USER=<your_username> PWORD=<your_password> CERT=<your_cert_file> python exp/main.py -e <your_experiment_name> -p <experiment_profile_name> -j <your_project_name> -c run_tbbs
```

There are other experiments commands like `run_tbbs2` and `run_bbs`.

5. Copy the results from the CloudLab nodes to your local machine.
```bash
USER=<your_username> PWORD=<your_password> CERT=<your_cert_file> python exp/main.py -e <your_experiment_name> -p <experiment_profile_name> -j <your_project_name> -c copy_op
```

## Credits
CloudLab API powder experiment scripts from [https://gitlab.flux.utah.edu/powder-profiles/powder-control](https://gitlab.flux.utah.edu/powder-profiles/powder-control)