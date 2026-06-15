#!/bin/bash
# ================================================================
#  ELK INIT — applies index templates for all honeypot indices
#  v2 - matches new unified log structure
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

ES="http://172.22.0.2:9200"

echo "[ELK-INIT] Waiting for Elasticsearch..."
until curl -sf "$ES/_cluster/health" > /dev/null; do sleep 3; done
echo "[ELK-INIT] Elasticsearch is ready."

# Delete old indices so templates apply cleanly on fresh start
#curl -s -X DELETE "$ES/honeypot-*" && echo "[ELK-INIT] Old indices deleted."

# ── TEMPLATE: honeypot-mqtt ──
echo "[ELK-INIT] Applying honeypot-mqtt template..."
curl -sf -X PUT "$ES/_index_template/honeypot-mqtt" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-mqtt-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":          {"type": "date"},
        "log_type":            {"type": "keyword"},
        "src_ip":              {"type": "ip"},
        "dst_ip":              {"type": "ip"},
        "src_port":            {"type": "integer"},
        "dst_port":            {"type": "integer"},
        "protocol":            {"type": "keyword"},
        "bytes_sent":          {"type": "integer"},
        "bytes_received":      {"type": "integer"},
        "is_internal":         {"type": "boolean"},
        "is_known_device":     {"type": "boolean"},
        "is_attack":           {"type": "boolean"},
        "attack_type":         {"type": "keyword"},
        "session_id":          {"type": "keyword"},
        "mqtt_action":         {"type": "keyword"},
        "client_id":           {"type": "keyword"},
        "topic":               {"type": "keyword"},
        "payload":             {"type": "text"},
        "payload_size":        {"type": "integer"},
        "qos":                 {"type": "integer"},
        "retain":              {"type": "integer"},
        "is_known_topic":      {"type": "boolean"},
        "session_msg_count":   {"type": "integer"},
        "session_topic_count": {"type": "integer"},
        "msg_rate_per_min":    {"type": "integer"},
        "session_duration_s":  {"type": "float"}
      }
    }
  }
}'

# ── TEMPLATE: honeypot-http ──
echo "[ELK-INIT] Applying honeypot-http template..."
curl -sf -X PUT "$ES/_index_template/honeypot-http" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-http-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":             {"type": "date"},
        "log_type":               {"type": "keyword"},
        "src_ip":                 {"type": "ip"},
        "dst_ip":                 {"type": "ip"},
        "src_port":               {"type": "integer"},
        "dst_port":               {"type": "integer"},
        "protocol":               {"type": "keyword"},
        "bytes_sent":             {"type": "integer"},
        "bytes_received":         {"type": "integer"},
        "is_internal":            {"type": "boolean"},
        "is_known_device":        {"type": "boolean"},
        "is_attack":              {"type": "boolean"},
        "attack_type":            {"type": "keyword"},
        "session_id":             {"type": "keyword"},
        "http_method":            {"type": "keyword"},
        "http_endpoint":          {"type": "keyword"},
        "http_status_code":       {"type": "integer"},
        "http_version":           {"type": "keyword"},
        "user_agent":             {"type": "keyword"},
        "content_type":           {"type": "keyword"},
        "body_size":              {"type": "integer"},
        "body":                   {"type": "text"},
        "session_req_count":      {"type": "integer"},
        "session_endpoint_count": {"type": "integer"},
        "req_rate_per_min":       {"type": "integer"},
        "session_duration_s":     {"type": "float"}
      }
    }
  }
}'

# ── TEMPLATE: honeypot-coap ──
echo "[ELK-INIT] Applying honeypot-coap template..."
curl -sf -X PUT "$ES/_index_template/honeypot-coap" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-coap-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":           {"type": "date"},
        "log_type":             {"type": "keyword"},
        "src_ip":               {"type": "ip"},
        "dst_ip":               {"type": "ip"},
        "src_port":             {"type": "integer"},
        "dst_port":             {"type": "integer"},
        "protocol":             {"type": "keyword"},
        "bytes_sent":           {"type": "integer"},
        "bytes_received":       {"type": "integer"},
        "is_internal":          {"type": "boolean"},
        "is_known_device":      {"type": "boolean"},
        "is_attack":            {"type": "boolean"},
        "attack_type":          {"type": "keyword"},
        "session_id":           {"type": "keyword"},
        "coap_method":          {"type": "keyword"},
        "coap_path":            {"type": "keyword"},
        "coap_response_code":   {"type": "keyword"},
        "is_known_path":        {"type": "boolean"},
        "payload_size":         {"type": "integer"},
        "payload":              {"type": "text"},
        "session_req_count":    {"type": "integer"},
        "session_path_count":   {"type": "integer"},
        "req_rate_per_min":     {"type": "integer"},
        "session_duration_s":   {"type": "float"}
      }
    }
  }
}'

# ── TEMPLATE: honeypot-cowrie ──
echo "[ELK-INIT] Applying honeypot-cowrie template..."
curl -sf -X PUT "$ES/_index_template/honeypot-cowrie" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-cowrie-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":         {"type": "date"},
        "log_type":           {"type": "keyword"},
        "log_source":         {"type": "keyword"},
        "src_ip":             {"type": "ip"},
        "dst_ip":             {"type": "ip"},
        "src_port":           {"type": "integer"},
        "dst_port":           {"type": "integer"},
        "protocol":           {"type": "keyword"},
        "bytes_sent":         {"type": "integer"},
        "bytes_received":     {"type": "integer"},
        "is_internal":        {"type": "boolean"},
        "is_known_device":    {"type": "boolean"},
        "is_attack":          {"type": "boolean"},
        "attack_type":        {"type": "keyword"},
        "session_id":         {"type": "keyword"},
        "eventid":            {"type": "keyword"},
        "username":           {"type": "keyword"},
        "password":           {"type": "keyword"},
        "command":            {"type": "text"},
        "session_duration_s": {"type": "float"},
        "file_url":           {"type": "keyword"},
        "login_success":      {"type": "boolean"},
        "login_attempt":      {"type": "boolean"},
        "message":            {"type": "text"}
      }
    }
  }
}'

# ── TEMPLATE: honeypot-network ──
echo "[ELK-INIT] Applying honeypot-network template..."
curl -sf -X PUT "$ES/_index_template/honeypot-network" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-network-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":      {"type": "date"},
        "log_type":        {"type": "keyword"},
        "log_source":      {"type": "keyword"},
        "src_ip":          {"type": "ip"},
        "dst_ip":          {"type": "ip"},
        "src_port":        {"type": "integer"},
        "dst_port":        {"type": "integer"},
        "protocol":        {"type": "keyword"},
        "bytes_sent":      {"type": "integer"},
        "bytes_received":  {"type": "integer"},
        "is_internal":     {"type": "boolean"},
        "is_known_device": {"type": "boolean"},
        "is_attack":       {"type": "boolean"},
        "attack_type":     {"type": "keyword"},
        "session_id":      {"type": "keyword"},
        "attack_name":     {"type": "keyword"},
        "packet_count":    {"type": "integer"},
        "pps":             {"type": "float"},
        "scanned_ports":   {"type": "integer"},
        "window_seconds":  {"type": "integer"}
      }
    }
  }
}'

# ── TEMPLATE: honeypot-platform ──
echo "[ELK-INIT] Applying honeypot-platform template..."
curl -sf -X PUT "$ES/_index_template/honeypot-platform" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["honeypot-platform-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":             {"type": "date"},
        "log_type":               {"type": "keyword"},
        "src_ip":                 {"type": "ip"},
        "dst_ip":                 {"type": "ip"},
        "src_port":               {"type": "integer"},
        "dst_port":               {"type": "integer"},
        "protocol":               {"type": "keyword"},
        "bytes_sent":             {"type": "integer"},
        "bytes_received":         {"type": "integer"},
        "is_internal":            {"type": "boolean"},
        "is_known_device":        {"type": "boolean"},
        "is_attack":              {"type": "boolean"},
        "attack_type":            {"type": "keyword"},
        "session_id":             {"type": "keyword"},
        "http_method":            {"type": "keyword"},
        "http_endpoint":          {"type": "keyword"},
        "http_status_code":       {"type": "integer"},
        "user_agent":             {"type": "keyword"},
        "body_size":              {"type": "integer"},
        "device":                 {"type": "keyword"},
        "command":                {"type": "keyword"},
        "device_protocol":        {"type": "keyword"},
        "login_attempt":          {"type": "boolean"},
        "login_success":          {"type": "boolean"},
        "username_tried":         {"type": "keyword"},
        "session_req_count":      {"type": "integer"},
        "session_endpoint_count": {"type": "integer"},
        "req_rate_per_min":       {"type": "integer"},
        "session_duration_s":     {"type": "float"}
      }
    }
  }
}'

echo "[ELK-INIT] All templates applied successfully."
