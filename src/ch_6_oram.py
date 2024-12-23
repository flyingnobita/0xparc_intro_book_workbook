# Implementation of a Binary-tree ORAM

# Example Tree Structure (D: Depth, H: Height)
#
# D3/H0   D3/H0   D3/H0   D3/H0   D3/H0   D3/H0   D3/H0   D3/H0
#   7       8       9       10      11      12      13      14
#  7:0     8:0     9:0     10:0    11:0    12:0    13:0    14:0
#  7:1     8:1     9:1     10:1    11:1    12:1    13:1    14:1
#    \     /         \     /         \     /         \     /
#      D2/H1          D2/H1          D2/H1          D2/H1
#        3              4              5              6
#       3:0            4:0            5:0            6:0
#       3:1            4:1            5:1            6:1
#         \            /                \            /
#              D1/H2                        D1/H2
#                1                            2
#               1:0                          2:0
#               1:1                          2:1
#                 \                          /
#                            D0/H3
#                             0:0
#                             0:1
#
#       STASH (Path ORAM only)
#               Stash_0
#               Stash_1
#                ...


from typing import Any, Optional
import warnings
import math
import random
from collections import deque


# Define a block
class Block:
    """A block in the ORAM tree structure.

    Attributes:
        address: Optional[int] - The block address, None if empty/dummy block
        data: Any - The data stored in the block, None if empty/dummy block
    """

    def __init__(self, address: Optional[int], data: Any):
        self.address = address
        self.data = data


# Define a bucket
class Bucket:
    """A bucket in the ORAM tree that can hold multiple blocks.

    Attributes:
        bucket_size: int - Number of slots in this bucket
        blocks: List[Block] - List of blocks stored in this bucket
    """

    def __init__(self, bucket_size: int):
        self.bucket_size = bucket_size
        self.blocks = [Block(None, None)] * bucket_size


# Define a class for the ORAM
class ORAM:
    """Binary-tree ORAM implementation supporting Path ORAM and basic binary tree ORAM.

    Attributes:
        bucket_size: int - Number of blocks per bucket
        number_of_blocks_needed: int - Minimum number of blocks required
        number_of_blocks_in_stash: int - Number of blocks in stash
        debug: bool - Enable debug printing
    """

    def __init__(
        self,
        bucket_size: int,
        number_of_blocks_needed: int,
        number_of_blocks_in_stash: Optional[int] = None,
        debug: bool = False,
    ):

        self.bucket_size = bucket_size
        self.number_of_blocks_needed = number_of_blocks_needed
        self.debug = debug

        # Number of buckets needed
        self.buckets_needed = math.ceil(self.number_of_blocks_needed / self.bucket_size)
        self.debug_print("Number of buckets needed: ", self.buckets_needed)

        # Number of levels (root node is level 0)
        self.tree_depth = int(math.ceil(math.log2(self.buckets_needed + 1))) - 1
        self.debug_print("Tree depth: ", self.tree_depth)

        # Total number of buckets
        self.number_of_buckets = int(math.pow(2, self.tree_depth + 1) - 1)
        self.debug_print("Actual number of buckets: ", self.number_of_buckets)

        # Total number of blocks
        self.number_of_blocks = self.number_of_buckets * self.bucket_size
        self.debug_print("Actual number of blocks: ", self.number_of_blocks)

        # Number of leaf nodes (N)
        self.number_of_leaf_nodes = int(math.pow(2, self.tree_depth))
        self.debug_print("Number of leaf nodes (N): ", self.number_of_leaf_nodes)

        # Generate a list of the leaf nodes indices
        self.leaf_nodes = self.build_leaf_nodes()
        self.debug_print("Leaf nodes: ", self.leaf_nodes)

        # Generate a list of the nodes indices
        self.path_nodes = self.build_path_nodes()
        self.debug_print("Path nodes: ", self.path_nodes)

        # Initialize buckets with empty slots
        self.buckets = [Bucket(self.bucket_size) for _ in range(self.number_of_buckets)]

        # Initialize Position Map
        # Fill the position map with None for all addresses
        self.position_map = {i: None for i in range(self.number_of_blocks)}

        # TODO: To be removed
        # Fill the position map with random path for each address
        # block_address_list = list(range(self.number_of_blocks))
        # random.shuffle(block_address_list)
        # for i in range(self.number_of_buckets):
        #     for j in range(self.bucket_size):
        #         address = block_address_list.pop()
        #         # Assign a block to a random bucket
        #         self.buckets[i].blocks[j] = Block(address, None)
        #         # Assign a random path to the block on the Position Map
        #         self.position_map[address] = self.generate_new_path_for_bucket(i)
        # print(
        #     "bucket_index: ",
        #     i,
        #     " path: ",
        #     self.position_map[address],
        #     " address: ",
        #     address,
        # )
        # self.print_position_map()

        # **For Path ORAM** - Initialize Stash
        if number_of_blocks_in_stash is None:
            # Set default size to be 2 x leaf nodes (i.e. store 2 paths worth of blocks)
            self.stash = deque([], maxlen=self.number_of_leaf_nodes * 2)
        else:
            self.stash = deque([], maxlen=number_of_blocks_in_stash)

    def build_leaf_nodes(self) -> list[int]:
        """Build list of leaf node indices in the binary tree.

        Returns:
            List of indices corresponding to leaf nodes.
        """
        leaf_nodes = []
        for i in range(2**self.tree_depth - 1, 2 ** (self.tree_depth + 1) - 1):
            leaf_nodes.append(i)
        return leaf_nodes

    def build_path_nodes(self) -> dict[int, list[int]]:
        """Build mapping of leaf nodes to their ancestor nodes.

        Returns:
            Dictionary mapping each leaf node to list of nodes in its path to root.
        """
        path_nodes = {}
        for leaf_index in self.leaf_nodes:
            ancestors = [leaf_index]
            i = leaf_index
            # add all the ancestors of i to the list
            for _ in range(self.tree_depth):
                if i % 2 == 0:
                    ancestors.append((i - 2) // 2)
                    i = (i - 2) // 2
                else:
                    ancestors.append((i - 1) // 2)
                    i = (i - 1) // 2

            path_nodes[leaf_index] = ancestors

        return path_nodes

    # DEBUG: For each bucket, print the contents of all the blocks in the bucket
    def debug_print_buckets(self) -> None:
        """Print contents of all buckets for debugging."""
        if self.debug:
            print("--------------------------------")
            print("Buckets: ")
            for i in range(self.number_of_buckets):
                for j in range(self.bucket_size):
                    if self.buckets[i].blocks[j] is not None:
                        print(
                            "Bucket: ",
                            i,
                            "\t",
                            "Block: ",
                            j,
                            "\t|",
                            "Address: ",
                            self.buckets[i].blocks[j].address,
                            "\t",
                            "Data: ",
                            self.buckets[i].blocks[j].data,
                        )
            print("--------------------------------")

    def debug_print_position_map(self) -> None:
        """Print the position map for debugging."""
        if self.debug:
            print("--------------------------------")
            print("Position map (address : path): ")
            for sub in self.position_map:
                print(sub, ":", self.position_map[sub])

    def debug_print_stash(self) -> None:
        """Print contents of the stash for debugging."""
        if self.debug:
            print("--------------------------------")
            print("Stash: ")
            for block in self.stash:
                print("Address: ", block.address, " Data: ", block.data)

    def debug_print(self, *args) -> None:
        """Print debug messages if debug mode is enabled.

        Args:
            *args: Values to print
        """
        if self.debug:
            print(*args)

    def add_block_to_root(self, address: int, data_star: Any) -> None:
        """Add a block to the first empty slot in root bucket.

        Args:
            address: Block address
            data_star: Data to store in block

        Raises:
            Warning if root bucket is full
        """

        # add the block to the first empty slot in the root bucket
        block_added = False
        for i in range(self.bucket_size):
            if self.buckets[0].blocks[i].address is None:
                self.buckets[0].blocks[i] = Block(address, data_star)
                block_added = True
                break

        # raise an error if the root bucket is full
        if not (block_added):
            self.debug_print_buckets()
            warnings.warn("Root bucket is full")

    def check_operations(self, op: str, address: int, data_star: Any) -> None:
        """Validate ORAM operation parameters.

        Args:
            op: Operation type ('read' or 'write')
            address: Block address
            data_star: Data for write operations

        Raises:
            Exception for invalid operations or addresses
        """

        if op == "read" and data_star is not None:
            raise Exception("Data is not required for read operation")

        if op == "write" and data_star is None:
            raise Exception("Data is required for write operation")

        if address >= self.number_of_blocks:
            raise Exception("Address is out of bounds")

    def generate_new_path_for_block(self) -> int:
        """Generate random new path for a block.

        Returns:
            New random path index
        """
        path_new = random.randint(
            2**self.tree_depth - 1, 2 ** (self.tree_depth + 1) - 2
        )
        return path_new

    def generate_new_path_for_bucket(self, bucket_index: int) -> int:
        """Generate valid path for a block in given bucket.

        Args:
            bucket_index: Index of bucket to generate path for

        Returns:
            Valid path index for the bucket
        """
        # Given a bucket index, generate a new path for the block

        if bucket_index in self.leaf_nodes:
            # If bucket is a leaf node, return the leaf node
            return bucket_index
        else:
            # If bucket is not a leaf node, randomly choose a children bucket
            children_buckets = [bucket_index * 2 + 1, bucket_index * 2 + 2]
            return self.generate_new_path_for_bucket(random.choice(children_buckets))

    # Algorithm 6.2: Accessing a block in the ORAM
    def access_binary_tree(self, op: str, address: int, data_star: Any = None) -> Any:
        """Access a block using Binary Tree ORAM protocol.

        Args:
            op: Operation type ('read' or 'write')
            address: Block address to access
            data_star: Data for write operations

        Returns:
            Data read from block for read operations
        """

        # Check if the operation is valid
        self.check_operations(op, address, data_star)

        # Line 1: Save the current path, l, of the block. Get a new random path,
        # l^*, for the block and update the position map.

        # Save the current path of the block
        path_current = self.position_map[address]

        # Generate a new path and update the position map of the block
        path_new = self.generate_new_path_for_block()
        self.position_map[address] = path_new

        # Line 2-4: Read every block in the path from leaf to root to find the block
        data = None
        if path_current is not None:
            # for each bucket along the path from leaf to root:
            for current_bucket in self.path_nodes[path_current]:

                # for each block in the bucket:
                for j in range(self.bucket_size):
                    # if address is in the bucket:
                    if self.buckets[current_bucket].blocks[j].address == address:
                        # save the data from the block
                        # wouldn't data_star be overwritten for a write operation?
                        # data_star = get data from the bucket
                        data = self.buckets[current_bucket].blocks[j].data
                        # remove block from bucket
                        self.buckets[current_bucket].blocks[j] = Block(None, None)
                        print(
                            "Block address: ",
                            address,
                            " removed from bucket: ",
                            current_bucket,
                            " block: ",
                            j,
                        )

        # Line 5: Add the block to the root bucket
        if op == "read":
            #  Add the data that was read to the root bucket
            self.add_block_to_root(address, data)
        else:
            # Add the data that we want to be written to the root bucket

            # If data_star contains the data that we want to write to,
            # we need to add it to the root bucket
            self.add_block_to_root(address, data_star)

        self.evict_binary_tree(address)

        return data

    # Algorithm 6.3: Evicting blocks in a Binary-tree ORAM
    def evict_binary_tree(self, address: int) -> None:
        """Evict blocks to the leaves after an access.

        Args:
            address: Address of block that was accessed
        """

        # For each level from root to (depth - 1):
        for i in range(self.tree_depth):

            # Pick 2 bucket indices randomly (at root, pick root bucket)
            buckets = (
                [0] if i == 0 else random.sample(range(2**i - 1, 2 ** (i + 1) - 1), 2)
            )

            # For each of the randomly chosen buckets, scan for a block
            # and add it to its child bucket
            # line 3-6
            for current_bucket in buckets:
                temp_block = None

                # Line 4: Remove and save a non-empty block from the current bucket
                # to a temporary slot
                for j in range(self.bucket_size):
                    if (
                        self.buckets[current_bucket].blocks[j].address is not None
                        and temp_block is None  # ensures we only remove 1 block
                    ):
                        temp_block = self.buckets[current_bucket].blocks[j]
                        self.buckets[current_bucket].blocks[j] = Block(None, None)

                # Line 5: Loop over the children of the bucket
                for k in range(1, 3):
                    child_index = current_bucket * 2 + k

                    if temp_block is not None:
                        # Check if current child lies in the path of the block
                        correct_child = (
                            child_index
                            in self.path_nodes[self.position_map[temp_block.address]]
                        )
                    else:
                        # a block was not previously removed, so no real block
                        # needs to be written
                        correct_child = False

                    # Scan the child buckets for a non-empty block
                    for j in range(self.bucket_size):

                        if (
                            self.buckets[child_index].blocks[j].address is None
                            and correct_child
                            and temp_block is not None
                        ):
                            # write the block from the temporary slot to the child's empty slot
                            self.buckets[child_index].blocks[j] = temp_block
                            self.debug_print(
                                "Block address: ",
                                temp_block.address,
                                " written to child bucket: ",
                                child_index,
                                " block: ",
                                j,
                            )
                            temp_block = None
                        else:
                            # dummy write: write the block back to itself
                            self.buckets[child_index].blocks[j] = self.buckets[
                                child_index
                            ].blocks[j]

                if temp_block is not None:
                    warnings.warn(
                        "Lost a block! Block cannot be written to child bucket\n "
                        + "block address: "
                        + str(temp_block.address)
                        + " \tblock data: "
                        + str(temp_block.data)
                        + " \tchild buckets: "
                        + str(current_bucket * 2 + 1)
                        + " "
                        + str(current_bucket * 2 + 2)
                    )
                    self.debug_print_position_map()
                    self.debug_print_buckets()

    # See Figure 1 of the Path ORAM paper
    def access_path_oram(self, op: str, address: int, data_star: Any = None) -> Any:
        """Access a block using Path ORAM protocol.

        Args:
            op: Operation type ('read' or 'write')
            address: Block address to access
            data_star: Data for write operations

        Returns:
            Data read from the block for read operations
            Previous data of the block for write operations
        """

        # Check if the operation is valid
        self.check_operations(op, address, data_star)

        # Line 1: Save the current path of the block
        path_current = self.position_map[address]

        # Line 2: Generate a new path and update the position map of the block
        path_new = self.generate_new_path_for_block()
        self.position_map[address] = path_new

        # Line 3-9: Move every block in the path to the Stash. If it's a read
        # opearation, read the data. If it's a write operation, update the data
        # in the block.
        data = None
        # If the block isn't being accessed for the first time
        if path_current is not None:
            # for each bucket along the pathfrom leaf to root:
            for current_bucket in self.path_nodes[path_current]:

                # for each block in the bucket:
                for j in range(self.bucket_size):

                    # for real blocks, save the block into the stash
                    if self.buckets[current_bucket].blocks[j].address is not None:
                        self.stash.append(self.buckets[current_bucket].blocks[j])
                        self.buckets[current_bucket].blocks[j] = Block(None, None)

        # Line 6-9: From the stash, read the block or update the block
        block_written = False
        for block in self.stash:
            if block.address == address:
                # Line 6: Read the data from the requested block
                # For read op, data is the current data in the block.
                # For write op, data is the previous data in the block.
                data = block.data
                # else:
                if op == "write":
                    # Line 7-9: For a write operation, update the data of the
                    # block in the stash
                    block.data = data_star
                    block_written = True
        # First time writing to address, add block to stash
        if op == "write" and not block_written:
            self.stash.append(Block(address, data_star))

        # Line 10-15: Starting from the leaf, write as many blocks from the stash
        # as possible
        # If the block isn't being accessed for the first time
        if path_current is not None:
            # Loop over the nodes in the path of the block from leaf to root
            for current_bucket in self.path_nodes[path_current]:

                # Loop over the blocks in the current bucket
                for j in range(self.bucket_size):

                    # Check that the slot is empty
                    if self.buckets[current_bucket].blocks[j].address is None:

                        # Loop over the stash
                        for block in self.stash:

                            # Retrieve the nodes along the path of the block
                            block_path_nodes = self.path_nodes[
                                self.position_map[block.address]
                            ]

                            # Check if the current bucket is in the path of the block
                            if current_bucket in block_path_nodes:

                                # write the block to the bucket
                                self.buckets[current_bucket].blocks[j] = block

                                # remove the block from the stash
                                self.stash.remove(block)
                                break
        return data


def execute_binary_tree_oram(
    oram: ORAM, op: str, address: int, data_star: Any = None
) -> None:
    """Execute and print results of a Binary Tree ORAM operation.

    Args:
        oram: ORAM instance
        op: Operation type ('read' or 'write')
        address: Block address to access
        data_star: Data for write operations
    """
    print(
        "OP: ",
        op,
        "\t",
        address,
        "\t",
        data_star,
        "\t",
        "- output: ",
        oram.access_binary_tree(op, address, data_star),
    )

    # oram.print_buckets()
    # oram.print_position_map()
    print("------------------------------------------------------------------")


def execute_path_oram(oram: ORAM, op: str, address: int, data_star: Any = None) -> None:
    """Execute and print results of a Path ORAM operation.

    Args:
        oram: ORAM instance
        op: Operation type ('read' or 'write')
        address: Block address to access
        data_star: Data for write operations
    """
    print(
        "OP: ",
        op,
        "\t",
        address,
        "\t",
        data_star,
        "\t",
        "- output: ",
        oram.access_path_oram(op, address, data_star),
    )

    # oram.print_stash()
    # oram.print_buckets()
    # oram.print_position_map()
    print("------------------------------------------------------------------")


def main():

    # Number of blocks needed
    number_of_blocks = 5
    print("Number of blocks needed: ", number_of_blocks)

    # Number of blocks per bucket
    Z = 2
    print("Number of blocks per bucket (Z): ", Z)

    # Number of blocks in stash
    number_of_blocks_in_stash = None
    print("Number of blocks in stash: ", number_of_blocks_in_stash)

    # Initialize ORAM
    oram = ORAM(Z, number_of_blocks, number_of_blocks_in_stash, debug=True)

    # Binary Tree ORAM
    print("--------------- Binary Tree ORAM ---------------")
    execute_binary_tree_oram(oram, "read", 1)
    execute_binary_tree_oram(oram, "write", 0, "data_0")
    execute_binary_tree_oram(oram, "write", 1, "data_1")
    execute_binary_tree_oram(oram, "write", 2, "data_2")
    execute_binary_tree_oram(oram, "read", 1)
    execute_binary_tree_oram(oram, "read", 2)

    # Path ORAM
    print("--------------- Path ORAM ---------------")
    execute_path_oram(oram, "write", 0, "data_0")
    execute_path_oram(oram, "read", 0)
    execute_path_oram(oram, "read", 1)
    execute_path_oram(oram, "write", 1, "data_1")
    execute_path_oram(oram, "read", 0)
    execute_path_oram(oram, "read", 1)
    execute_path_oram(oram, "write", 1, "data_1")
    execute_path_oram(oram, "write", 3, "data_3")
    execute_path_oram(oram, "read", 2)
    execute_path_oram(oram, "write", 2, "data_2")
    execute_path_oram(oram, "read", 2)


main()
