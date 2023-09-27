import pydot

def draw(parent_name, child_name):
    # if the string is too long, I shorten it to improve readability
    if len(parent_name) > 32:
        parent_name = parent_name[0:7] + '...'
    if len(child_name) > 32:
        child_name = child_name[0:7] + '...'
    edge = pydot.Edge(parent_name, child_name)
    graph.add_edge(edge)
    
def visit(node, parent=None):
    for k,v in node.items():
        if isinstance(v, dict):
            # We start with the root node whose parent is None
            # we don't want to graph the None node
            if parent:
                draw(parent, k)
            visit(v, k)
        else:
            draw(parent, k)
            # drawing the label using a distinct name
            draw(k, k+'_'+str(v))

graph = pydot.Dot(graph_type='graph')