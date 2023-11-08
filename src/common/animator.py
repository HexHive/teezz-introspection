import logging
from clang.cindex import Cursor, Type
from graphviz import Digraph


################################################################################
# LOGGING
################################################################################

log = logging.getLogger(__name__)
log.setLevel(logging.ERROR)


class Animator(object):
    def __init__(self):
        self._ga = Digraph()
        self._ga.attr("node", shape="box")
        self._nodes = dict()

    def addEdge(self, start: [Cursor, Type], end: [Cursor, Type], color="black"):
        log.info("Adding Edge")
        startNode = self.getNode(start)
        endNode = self.getNode(end)

        self._ga.edge(startNode, endNode, color=color)

    def render(self, fileName, view=False):
        self._ga.render(fileName, view=view)

    def mark_call(self, node):
        self._set_node_color(node, "red")

    def _set_node_color(self, node, color="black"):
        node_id = self.getNode(node)
        self._ga.node(node_id, color=color)

    def getNode(self, node: [Cursor, Type]):
        node_id = str(node.__hash__())
        if not node_id in self._nodes:
            self._nodes[node_id] = self._ga.node(node_id, node.spelling)
        return node_id
