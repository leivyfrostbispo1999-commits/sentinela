import json
import os
import time
import uuid
from kafka import KafkaConsumer
from neo4j import GraphDatabase

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
TOPICS = ["enriched_logs", "raw_logs", "security_alerts"] # Escuta alertas para mapear incidentes

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "sentinela-graph")

class GraphEngine:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self._initialize_constraints()
        print("Graph Engine conectado ao Neo4j com suporte XDR & Semantic Enrichment.")

    def _initialize_constraints(self):
        with self.driver.session() as session:
            # Constraints para unicidade e performance
            constraints = [
                "CREATE CONSTRAINT tenant_id IF NOT EXISTS FOR (t:Tenant) REQUIRE t.id IS UNIQUE",
                "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (ip:IP) REQUIRE ip.address IS UNIQUE",
                "CREATE CONSTRAINT user_name IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
                "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
                "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
                "CREATE CONSTRAINT incident_id IF NOT EXISTS FOR (i:Incident) REQUIRE i.id IS UNIQUE",
                "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
                "CREATE INDEX ip_tenant IF NOT EXISTS FOR (ip:IP) ON (ip.tenant_id)",
            ]
            for c in constraints:
                try: session.run(c)
                except: pass

    def close(self):
        self.driver.close()

    def process_event(self, log):
        with self.driver.session() as session:
            session.execute_write(self._sync_graph, log)

    @staticmethod
    def _sync_graph(tx, log):
        tenant_id = log.get("tenant_id", "default")
        source_ip = log.get("source_ip") or log.get("ip")
        event_type = str(log.get("event_type", "UNKNOWN")).upper()
        ts = log.get("ts") or log.get("timestamp")
        
        # 1. Tenant & Entity Base (Semantic Enrichment)
        tx.run("""
            MERGE (t:Tenant {id: $tid})
            SET t.last_seen = $ts
            
            MERGE (ip:IP {address: $ip})
            SET ip.tenant_id = $tid, 
                ip.last_seen = $ts,
                ip.risk_score = COALESCE($risk, ip.risk_score, 0),
                ip.country = $country
            
            MERGE (ip)-[:BELONGS_TO]->(t)
        """, tid=tenant_id, ip=source_ip, ts=ts, 
             risk=log.get("threat_score"), 
             country=log.get("enrichment_geoip", {}).get("country"))

        # 2. XDR Domain: Identity & Logon
        if any(x in event_type for x in ["LOGIN", "BRUTE_FORCE", "AUTH"]):
            username = log.get("username") or "unknown"
            tx.run("""
                MERGE (u:User {name: $user})
                SET u.tenant_id = $tid, u.last_seen = $ts
                MERGE (ip:IP {address: $ip})
                MERGE (ip)-[r:LOGGED_IN_FROM {status: $status, ts: $ts}]->(u)
                MERGE (u)-[:AUTHENTICATED_TO]->(h:Host {id: $host})
            """, user=username, ip=source_ip, tid=tenant_id, ts=ts, 
                 status=event_type, host=log.get("target_host", "internal-network"))

        # 3. XDR Domain: Endpoint (Processes & Files)
        if "ENDPOINT" in event_type or "PROCESS" in event_type or "SHELL" in event_type:
            host_id = log.get("target_host", "unknown-host")
            proc_name = log.get("process_name") or "unknown_proc"
            tx.run("""
                MERGE (h:Host {id: $host})
                SET h.tenant_id = $tid, h.last_seen = $ts, h.criticality = $crit
                
                MERGE (p:Process {id: $pid_key})
                SET p.name = $proc, p.cmd = $cmd, p.ts = $ts, p.tenant_id = $tid
                
                MERGE (h)-[:TOUCHED_ASSET]->(p)
                MERGE (ip:IP {address: $ip})-[:CONNECTED_TO]->(h)
            """, host=host_id, tid=tenant_id, ts=ts, crit=log.get("asset_criticality", "medium"),
                 pid_key=f"{host_id}:{log.get('pid', '0')}", proc=proc_name, 
                 cmd=log.get("command_line"), ip=source_ip)
            
            if log.get("parent_process"):
                tx.run("""
                    MERGE (parent:Process {name: $parent})
                    MERGE (child:Process {name: $child})
                    MERGE (parent)-[:SPAWNED_PROCESS]->(child)
                """, parent=log.get("parent_process"), child=proc_name)

        # 4. XDR Domain: Cloud API
        if "CLOUD" in event_type:
            acc = log.get("cloud_account", "unknown-acc")
            tx.run("""
                MERGE (c:CloudAccount {id: $acc})
                SET c.tenant_id = $tid, c.provider = $prov
                MERGE (ip:IP {address: $ip})
                MERGE (ip)-[:CALLED_API {call: $api, ts: $ts}]->(c)
            """, acc=acc, tid=tenant_id, prov=log.get("cloud_provider", "AWS"),
                 ip=source_ip, api=log.get("api_call"), ts=ts)

        # 5. Security Domain: Alerts & Incidents
        alert_id = log.get("event_id")
        if alert_id and (log.get("severity") or log.get("status") == "AI_ANOMALY"):
            tx.run("""
                MERGE (a:Alert {id: $aid})
                SET a.type = $etype, a.severity = $sev, a.ts = $ts, a.mitre_id = $mitre
                MERGE (ip:IP {address: $ip})-[:CAUSED]->(a)
                
                WITH a
                MATCH (t:Tenant {id: $tid})
                MERGE (a)-[:GENERATED_ALERT]->(t)
            """, aid=alert_id, etype=event_type, sev=log.get("severity", "LOW"), 
                 ts=ts, mitre=log.get("mitre_id"), ip=source_ip, tid=tenant_id)

            if log.get("campaign_id"):
                tx.run("""
                    MERGE (camp:Campaign {id: $cid})
                    SET camp.tenant_id = $tid, camp.last_seen = $ts
                    MATCH (a:Alert {id: $aid})
                    MERGE (a)-[:PART_OF_CAMPAIGN]->(camp)
                """, cid=log.get("campaign_id"), tid=tenant_id, ts=ts, aid=alert_id)

    def run(self):
        consumer = KafkaConsumer(
            *TOPICS,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id="graph-engine-v1",
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8"))
        )
        
        print("Graph Engine aguardando eventos...")
        for message in consumer:
            try:
                self.process_event(message.value)
            except Exception as e:
                print(f"Erro no mapeamento de grafo: {e}")

if __name__ == "__main__":
    # Pequeno delay para o Neo4j subir
    time.sleep(15)
    engine = GraphEngine()
    try:
        engine.run()
    finally:
        engine.close()
