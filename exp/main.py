import argparse
import logging
import multiprocessing as multi
import os
import subprocess
import sys
from typing import Dict

from powder import rpc
from powder.experiment import Node, PowderExperiment

logging.basicConfig(
    level=logging.DEBUG, format="[%(asctime)s] - %(levelname)s - %(message)s"
)

parser = argparse.ArgumentParser(description="Experiment Management")
parser.add_argument(
    "--experiment_name",
    "-e",
    type=str,
    required=True,
    help="Name of the cloudlab experiment",
)
parser.add_argument(
    "--profile_name",
    "-p",
    type=str,
    required=True,
    help="Name of the cloudlab profile to use",
)
parser.add_argument(
    "--project_name",
    "-j",
    type=str,
    required=True,
    help="Name of the cloudlab project",
)
parser.add_argument(
    "--command",
    "-c",
    type=str,
    default="init",
    choices=[
        "init",
        "stop",
        "status",
        "copy",
        "setup",
        "sync_env",
        "run",
        "run_exp",
        "copy_op",
        "terminate",
    ],
    help="Command to execute on the experiment",
)


def get_nodes(experiment_name: str, project_name: str, profile_name: str):
    exp = PowderExperiment(
        experiment_name=experiment_name,
        project_name=project_name,
        profile_name=profile_name,
    )
    exp._get_status()

    status = exp.status

    # logging.debug(f"experiment status: {status}")

    if status != exp.EXPERIMENT_READY:
        logging.error(
            f"experiment {experiment_name} is not ready. Current status: {status}"
        )
        sys.exit(1)
    return exp.nodes


def copy_code(nodes_dict: Dict[str, Node]):
    root_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../verisso")
    )

    if not os.path.exists(root_dir):
        logging.error(f"Root directory {root_dir} does not exist.")
        sys.exit(1)

    try:
        subprocess.run(
            [
                "tar",
                "--exclude=venv",
                "--exclude=.git",
                "--exclude=.idea",
                "--exclude=target",
                "--exclude=__pycache__",
                "--exclude=exp",
                "-czf",
                "verisso.tar.gz",
                "-C",
                root_dir,
                ".",
            ],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logging.error(f"Error compressing code directory: {e}")
        sys.exit(1)

    with multi.Pool(processes=len(nodes_dict)) as pool:
        pool.map(copy_code_to_node, nodes_dict.values())

    # Remove the tar.gz file after copying
    try:
        os.remove("verisso.tar.gz")
        logging.info("Removed verisso.tar.gz after copying.")
    except Exception as e:
        logging.warning(f"Could not remove verisso.tar.gz: {e}")


def copy_code_to_node(node: Node):
    try:
        # Copying tar.gz file to the node
        subprocess.run(
            [
                "scp",
                "-o",
                "StrictHostKeyChecking no",
                "-r",
                "verisso.tar.gz",
                f"{os.environ['USER']}@{node.hostname}:~/",
            ],
            check=True,
            input="yes\n",
            text=True,
        )
        # Extracting the tar.gz file on the node
        subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking no",
                f"{os.environ['USER']}@{node.hostname}",
                # "sudo rm -rf ~/verisso && ",
                "mkdir -p ~/verisso && tar --warning=no-unknown-keyword -xzf ~/verisso.tar.gz -C ~/verisso/",
            ],
            check=True,
        )
        logging.info(f"Code copied to node {node.hostname}")
    except Exception as e:
        logging.error(f"Error copying code to node {node.hostname}: {e}")
        sys.exit(1)


def copy_envs(nodes_dict: Dict[str, Node]):
    try:
        with multi.Pool(processes=len(nodes_dict)) as pool:
            pool.map(copy_env_to_node, nodes_dict.values())
        logging.info("Copied .env files to all nodes.")
    except Exception as e:
        logging.error(f"Error copying .env files to nodes: {e}")
        sys.exit(1)


def copy_env_to_node(node: Node):
    try:
        # Copying the .env file to the node
        subprocess.run(
            [
                "scp",
                "-o",
                "StrictHostKeyChecking no",
                ".env",
                f"{os.environ['USER']}@{node.hostname}:~/verisso/",
            ],
            check=True,
        )
        # logging.info(f".env file copied to node {node.hostname}")
    except Exception as e:
        logging.error(f"Error copying .env file to node {node.hostname}: {e}")
        sys.exit(1)


def setup_nodes(nodes_dict: Dict[str, Node]):
    with multi.Pool(processes=len(nodes_dict)) as pool:
        pool.map(setup_node, nodes_dict.values())


def setup_node(node: Node):
    client_id = node.client_id
    # Get digit from client_id can have multiple digits
    # id = int("".join(filter(str.isdigit, client_id))) 
    try:
        subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking no",
                f"{os.environ['USER']}@{node.hostname}",
                # Install rust
                "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && ",
                "source $HOME/.cargo/env && ",
                "cd ~/verisso && cargo build --release --bin as && cargo build --release --bin signer && cargo build --release --bin client"
            ],
            check=True,
        )
        logging.info(f"Setup completed on node {node.hostname}")
    except Exception as e:
        logging.error(f"Error setting up node {node.hostname}: {e}")
        sys.exit(1)


def run(nodes_dict: Dict[str, Node]):
    try:
        with multi.Pool(processes=len(nodes_dict)) as pool:
            pool.map(run_node, nodes_dict.values())

        logging.info("Experiment completed successfully.")
    except Exception as e:
        logging.error(f"Error running nodes: {e}")
        sys.exit(1)


def run_exp(node: Node):
    # Copy op folder from ssh to my local
    try:
        subprocess.run(
            [
                 "ssh",
                "-o",
                "StrictHostKeyChecking no",
                f"{os.environ['USER']}@{node.hostname}",
                "~/verisso/target/release/client"
            ],
            check=True,
        )
        logging.info(f"")
    except Exception as e:
        logging.error(f"")
        sys.exit(1)


def run_node(node: Node):
    client_id = node.client_id
    # Get digit from client_id can have multiple digits
    id = int("".join(filter(str.isdigit, client_id)))
    # logging.info(f"Running node {node.hostname} with client_id {client_id} and id {id}")
    run_command = ""
    if id == 0:
        run_command = f"NODE_ID=0 TOTAL_NODES=8 ~/verisso/target/release/as"
    else:
        run_command = f"cd ~/verisso && NODE_ID={id} TOTAL_NODES=8 ~/verisso/target/release/signer"

    try:
        logging.info(f"Starting node {node.hostname} with id {id}")
        subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking no",
                f"{os.environ['USER']}@{node.hostname}",
                # provide permissions to the scripts
                "sudo chmod +x ~/verisso/scripts/*.sh && ",
                "cd ~/verisso && sudo ./scripts/kill.sh && ", # kill previous processes if any
                "cd ~/verisso && ",
                # # "pkill -x as || true && pkill -x signer || true && ",
                "chmod +x ~/verisso/target/release/{as,signer,client} && ",
                run_command,
            ],
            check=True,
        )
        # logging.info(f"Node {node.hostname} started successfully.")
    except Exception as e:
        logging.error(f"Error starting node {node.hostname}: {e}")
        sys.exit(1)


def copy_op(node: Node):
    # Copy op folder from ssh to my local
    try:
        subprocess.run(
            [
                "scp",
                "-o",
                "StrictHostKeyChecking no",
                "-r",
                f"{os.environ['USER']}@{node.hostname}:~/verisso/op",
                ".",
            ],
            check=True,
        )
        logging.info(f"Copied op folder from node {node.hostname} to local.")
    except Exception as e:
        logging.error(f"Error copying op folder from node {node.hostname}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    args = parser.parse_args()
    logging.info(
        f"Starting experiment: {args.experiment_name} with profile: {args.profile_name} in project: {args.project_name}"
    )
    params = {
        "experiment_name": args.experiment_name,
        "profile_name": args.profile_name,
        "project_name": args.project_name,
    }

    if args.command == "init":
        rval, response = rpc.start_experiment(
            args.experiment_name, args.project_name, args.profile_name
        )
        logging.info(f"Start experiment response: {response}")
        logging.info(f"Start experiment return value: {rval}")
    elif args.command == "stop":
        rval, response = rpc.terminate_experiment(
            args.project_name, args.experiment_name
        )
        logging.info(f"Terminate experiment response: {response}")
        logging.info(f"Terminate experiment return value: {rval}")

    nodes = get_nodes(args.experiment_name, args.project_name, args.profile_name)
    if args.command == "status":
        logging.info(
            f"Nodes in experiment {args.experiment_name}: {[node.hostname for node in list(nodes.values())]}"
        )
    elif args.command == "copy":
        copy_code(nodes)
    elif args.command == "setup":
        setup_nodes(nodes)
    elif args.command == "sync_env":
        copy_envs(nodes)
    elif args.command == "run":
        run(nodes)
    elif args.command == "run_exp":
        run_exp(nodes["node0"])
    elif args.command == "copy_op":
        copy_op(nodes["node0"])
    elif args.command == "terminate":
        rval, response = rpc.terminate_experiment(
            args.project_name, args.experiment_name
        )
        logging.info(f"Terminate experiment response: {response}")
        logging.info(f"Terminate experiment return value: {rval}")

        # rval, response = rpc.get_experiment_status(
        #     args.project_name, args.experiment_name
        # )
        # logging.info(f"Get experiment status response: {response}")
        # logging.info(f"Get experiment status return value: {rval}")

    # """Start the experiment and wait for READY or FAILED status."""
    # # logging.info("starting experiment {}".format(args.experiment_name))
    # rval, response = rpc.get_experiment_status(args.experiment_name, args.project_name)
    # logging.info("get_experiment_status response: {}".format(response))
    # logging.info("get_experiment_status return value: {}".format(rval))
