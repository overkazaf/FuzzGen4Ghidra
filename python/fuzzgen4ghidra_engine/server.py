import argparse
import logging
import socket
import threading

from .engine import FuzzGenEngine
from .protocol import parse_command, ok, error, progress

HOST = "127.0.0.1"
PORT = 13371

logging.basicConfig(
    level=logging.INFO,
    format="[fuzzgen4ghidra] %(levelname)s %(message)s",
)
logger = logging.getLogger("fuzzgen4ghidra")

HANDLERS = {
    "init": lambda eng, p: eng.init(p["binary_path"]),
    "analyze_params": lambda eng, p: eng.analyze_params(
        int(p["func_addr"], 16) if isinstance(p["func_addr"], str) else p["func_addr"],
        p["ghidra_signature"],
    ),
    "generate_harness": lambda eng, p: eng.generate_harness(
        func_addr=int(p["func_addr"], 16) if isinstance(p["func_addr"], str) else p["func_addr"],
        func_name=p["func_name"],
        ghidra_signature=p["ghidra_signature"],
        target_binary=p["target_binary"],
        fmt=p.get("fmt", "afl"),
        output_dir=p.get("output_dir"),
    ),
}


def handle_client(conn: socket.socket, engine: FuzzGenEngine):
    with conn.makefile("r", encoding="utf-8") as reader, \
         conn.makefile("w", encoding="utf-8") as writer:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = parse_command(line)
                logger.info("CMD: %s", cmd.type)
                if cmd.type == "scan_targets":
                    def cb(data):
                        writer.write(progress(data).to_json() + "\n")
                        writer.flush()
                    result = engine.scan_targets(
                        cmd.params.get("ghidra_functions", []),
                        progress_callback=cb,
                    )
                    resp = ok({"targets": result})
                else:
                    handler = HANDLERS.get(cmd.type)
                    if handler is None:
                        resp = error(f"Unknown command: {cmd.type}")
                    else:
                        result = handler(engine, cmd.params)
                        resp = ok(result)
            except Exception as e:
                logger.exception("Error handling command")
                resp = error(str(e))
            writer.write(resp.to_json() + "\n")
            writer.flush()


def main():
    parser = argparse.ArgumentParser(description="FuzzGen4Ghidra analysis engine")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.verbose:
        logging.getLogger("fuzzgen4ghidra").setLevel(logging.DEBUG)

    engine = FuzzGenEngine()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    logger.info("FuzzGen4Ghidra engine listening on %s:%d", args.host, args.port)

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Client connected from %s", addr)
            thread = threading.Thread(target=handle_client, args=(conn, engine), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
