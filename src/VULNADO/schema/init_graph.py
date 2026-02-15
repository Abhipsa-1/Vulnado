from neontology import init_neontology
from neontology.graphengines import Neo4jConfig

print("Initializing graph...")
def init_graph():
    config = Neo4jConfig(
        uri="neo4j+ssc://e023f02b.databases.neo4j.io",
        username="neo4j",
        password="Mo_q36wZ3-VJtjgE5RtRUOIbS4uFP2O83Ne1krlay9A"
    )
    init_neontology(config)
    print("Graph initialized with Neo4j configuration.")
