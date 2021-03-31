import networkx as nx
import matplotlib.pyplot as plt
import pydot
from networkx.drawing.nx_pydot import graphviz_layout
import bs4
from bs4 import BeautifulSoup as Soup
import re
import json
import hashlib

# Settings
# Do we consider hashes invalid if they do not have at least the specified hex length?
STRICT_HEX_LENGTH = True  # Ideally this should be true
# How many characters we need in a hex string for it to be considered a valid hash
RESTRICT_HEX_LENGTH_TO = 64  # Ideally should be set to 64
# Does a hash have to have a length equal or at least equal to RESTRICT_HEX_LENGTH_TO
ALLOW_OVER_MAX_LENGTH_HEX = True  # Ideally should be false


class Node:
    def __init__(self, name, hash_text, hash_hex):
        self.name = name
        self.hash_text = hash_text
        self.extract_data()
        self.number = int(hash_text.split('+')[0])
        self.hash_hex = hash_hex
        self.follows = None
        self.followed_by = []
        self.valid = self.validate()

    def __str__(self):
        return f"{self.number} from {self.name}"

    def __repr__(self):
        return f"{self.number} from {self.name}"

    def validate(self):
        # To be valid, it needs to link to the previous node correctly,
        # the hash hex needs to be the value received when hashing the plain text, and
        # both hashes need to be valid hex.

        # If a node does not follow anything, return None
        if self.follows is None:
            return None

        # Check it links to the previous node correctly
        if int(self.previous_hash, 16) != int(self.follows.hash_hex, 16):
            return False
        combined_hash_text = f"{self.hash_text}\n"
        hashed_value = hashlib.sha256(combined_hash_text.encode()).hexdigest()
        if int(self.hash_hex, 16) != int(hashed_value, 16):
            return False
        if not self.valid_hex_hash(str(self.hash_hex)):
            return False
        if not self.valid_hex_hash(str(self.previous_hash)):
            return False
        return True

    def valid_hex_hash(self, hash_hex):
        try:
            int(hash_hex, 16)
            # Remove any whitespace
            hash_hex = ''.join(hash_hex.split())
            return hash_hex[0] == '0' and hash_hex[1].isnumeric() and len(hash_hex) == 64
        except ValueError:
            return False

    def add_to_graph(self, graph):
        # Presume that we have already been added to the graph by someone above us
        # Only need to add people below us
        for follower in self.followed_by:
            graph.add_node(follower)
            graph.add_edge(self, follower)
            follower.add_to_graph(graph)

    def extract_data(self):
        parts = self.hash_text.split('+')
        self.previous_hash = parts[2].replace(' ', '')

    def add_node(self, node):
        if int(node.previous_hash, 16) == int(self.hash_hex, 16):
            self.followed_by.append(node)
            node.follows = self
            node.valid = node.validate()
            return True

        for follower in self.followed_by:
            follower.add_node(node)


def find_hash_text(array):
    for block in array:
        if block.count('+') == 3:
            # We also need to check if the hash is valid hex
            # Need this due to an edge case where there is something else with 3 +'s in it and there is a space in the prediction
            # Which means that the other thing is chosen as the hex
            try:
                int(block, 16)
                return block
            except ValueError:
                continue
    # If we get here, no lines contained 3 +'s and was a valid hex hash
    # So the hash must have been split by spaces
    return remerge_hash_text(array)


def find_hash_hex(array):
    for line in array:
        try:
            int(line, 16)
            # Need to check the hash has 64 hex characters
            if STRICT_HEX_LENGTH and len(line) == RESTRICT_HEX_LENGTH_TO:
                return line
            elif STRICT_HEX_LENGTH and len(line) >= RESTRICT_HEX_LENGTH_TO and ALLOW_OVER_MAX_LENGTH_HEX:
                return line
            elif not STRICT_HEX_LENGTH:
                return line
            else:
                continue
        except ValueError:
            continue


def remerge_hash_text(words):
    result = []
    num_plusses_spotted = 0
    joining = False
    for word in words:
        if word.count('+') > 0:
            num_plusses_spotted += word.count('+')
            joining = True
        if joining:
            if num_plusses_spotted == 2:
                # We are building the previous blocks hash
                word = ''.join(word.split())
            result.append(word)
        if num_plusses_spotted >= 3:
            joining = False
            combined_result = " ".join(result)
            return re.sub(r'\s*\+\s*', '+', combined_result)


def read_data():
    soup = Soup(open("comments.html"), "html.parser")
    comments = soup.find_all('div', {'class', 'comment-container'})
    top_level_comments = []
    parsed_comments = []
    for comment in comments:
        comment_data = {}
        parsed_comments.insert(0, comment_data)

        # Get the author
        author_data = comment.find('a', {'class', 'comment-profile-link'})
        author_name = author_data.text
        comment_data['name'] = " ".join(author_name.split())
        for br in comment.find_all("br"):
            br.replace_with("\n")

        content = comment.find('div', {'class': 'comment-content'})
        content_text = content.text
        # content_text.append(content.text)
        lines = content_text.split('\n')
        words = []
        for line in lines:
            # for line in content_text:
            line = line.replace(':', ' ')
            line = line.replace('"', ' ')
            line = line.replace("'", ' ')
            line = re.sub(' +', ' ', line)
            line = re.sub('\s+\+\s+', '+', line)
            for word in line.split():
                # Replace colon with space as can cause issues detecting the hashes
                words.append(word)
        # We now have an array of words that
        # Unfortunately, if someone's prediction included spaces, the hash text has now been broken up
        # We now need to remerge it

        # Note: This will completely break if someone uses a + somewhere else in their comment
        comment_data['hash_text'] = find_hash_text(words)
        comment_data['hash_hex'] = find_hash_hex(words)

        # Check that both hashes are valid hex
        if comment_data['hash_hex'] is not None:
            try:
                int(comment_data['hash_hex'], 16)
            except ValueError:
                comment_data['hash_hex'] = None

        if comment_data['hash_text'] is not None:
            try:
                split = comment_data['hash_text'].split('+')
                int(split[2], 16)
            except (ValueError, IndexError):
                comment_data['hash_text'] = None

    valid_comments = []
    for comment in parsed_comments:
        if comment['hash_text'] is not None \
                and comment['hash_hex'] is not None \
                and len(comment['hash_text']) > 0 \
                and len(comment['hash_hex']) > 0:
            valid_comments.append(comment)

    valid_comments.sort(key=get_number)
    return valid_comments


def process_data(data):
    # As of time of writing, there are essentially two completely separate branches of BuckCoin due to a typo.
    # Comment out either of these head nodes in order to see the branch each node is the head of.

    # head = Node("Richard Buckland", "1+Service NSW+0f603b5f322a16568bf7b0acff51008466408cdccbfeff675118bbde8ca49b50+11",
    #            "083eaee1b4dc40f7ffa14d23b3ea78059b5cb3b529dc9e24f508160bcddd6e33")
    head = Node("Calvin Long", "24+Transport NSW+012313510be6865ad45f100211abfb110779a8cbd868636dd4f75a2b839180f+3",
                "02ae526285a5e2d8f5cf585bf8fb6f80532a066c3935ff1161754a1f49e7d678")
    nodes = []
    for comment in data:
        new_node = Node(comment['name'],
                        comment['hash_text'], comment['hash_hex'])
        head.add_node(new_node)
        nodes.append(new_node)
    with open("output.json", 'w') as f:
        json.dump(data, f)
    display_graph(head)
    return head, nodes


def get_number(comment):
    return int(comment['hash_text'].split('+')[0])


def display_graph(head):
    G = nx.Graph()
    G.add_node(head)
    head.add_to_graph(G)
    colour_map = []
    for node in G:
        colour = ''
        if node.valid is True:
            colour = 'green'
        if node.valid is False:
            colour = 'red'
        if node.valid is None:
            colour = 'grey'
        colour_map.append(colour)
    pos = nx.nx_pydot.graphviz_layout(G, prog="dot")
    nx.draw(G, pos, node_color=colour_map, with_labels=True, arrows=True)
    plt.show()


if __name__ == "__main__":
    data = read_data()
    process_data(data)
