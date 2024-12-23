from collections import deque
from typing import TYPE_CHECKING
from src.ch_6_oram import Block, Bucket, ORAM
import pytest

if TYPE_CHECKING:
    from pytest_mock import MockerFixture


class TestORAM:
    @pytest.fixture
    def oram_instance(self) -> ORAM:
        """
        Create a basic ORAM instance for testing.

        Returns:
            ORAM: A configured ORAM instance.
        """
        return ORAM(bucket_size=2, number_of_blocks_needed=28, debug=False)

    def test_invalid_operations(self, oram_instance: ORAM) -> None:
        """
        Test error handling for invalid operations.

        Args:
            oram_instance: Fixture providing ORAM instance.
        """
        with pytest.raises(Exception):
            oram_instance.access_binary_tree(
                "read", 0, "data"
            )  # Read shouldn't have data

        with pytest.raises(Exception):
            oram_instance.access_binary_tree("write", 0)  # Write needs data

        with pytest.raises(Exception):
            oram_instance.access_binary_tree("write", 999, "data")  # Invalid address

    def test_binary_tree_oram_operations(self, oram_instance: ORAM) -> None:
        """
        Test multiple write and read operations to verify data consistency.

        Args:
            oram_instance: Fixture providing ORAM instance.
        """
        test_data = {i: f"data_{i}" for i in range(4)}

        # Write multiple blocks
        for addr, data in test_data.items():
            oram_instance.access_binary_tree("write", addr, data)

        # Read and verify
        for addr, expected_data in test_data.items():
            result = oram_instance.access_binary_tree("read", addr)
            assert result == expected_data

    def test_path_oram_operations(self, oram_instance: ORAM) -> None:
        """
        Test Path ORAM specific operations with 50 mixed read/write operations.

        Args:
            oram_instance: Fixture providing ORAM instance.
        """
        # Test data for multiple addresses
        test_data = {i: None for i in range(15)}

        # Perform 50 operations (mix of reads and writes)
        for i in range(50):
            address = i % 15  # Cycle through addresses 0-14

            if i % 2 == 0:  # Alternate between writes and reads
                # Write operation
                new_data = (
                    f"data_{address}_v{i//15}"  # Version the data to track changes
                )
                write_result = oram_instance.access_path_oram(
                    "write", address, new_data
                )

                # Verify write result matches previous data
                assert write_result == test_data[address]

                # Update data versions
                test_data[address] = new_data
            else:
                # Read operation
                read_result = oram_instance.access_path_oram("read", address)
                assert read_result == test_data[address]
