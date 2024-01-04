package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	e2e "github.com/cometbft/cometbft/test/e2e/pkg"
)

// Tests that block headers are identical across nodes where present.
func TestBlock_Header(t *testing.T) {
	blocks := fetchBlockChain(t)
	testNode(t, func(t *testing.T, node e2e.Node) {
		if node.Mode == e2e.ModeSeed || node.EnableCompanionPruning {
			return
		}

		client, err := node.Client()
		require.NoError(t, err)
		status, err := client.Status(ctx)
		require.NoError(t, err)

		first := status.SyncInfo.EarliestBlockHeight
		last := status.SyncInfo.LatestBlockHeight
		if node.RetainBlocks > 0 {
			first++ // avoid race conditions with block pruning
		}

		for _, block := range blocks {
			if block.Header.Height < first {
				continue
			}
			if block.Header.Height > last {
				break
			}
			resp, err := client.Block(ctx, &block.Header.Height)
			require.NoError(t, err)

			require.Equal(t, block, resp.Block,
				"block mismatch for height %d", block.Header.Height)

			require.NoError(t, resp.Block.ValidateBasic(),
				"block at height %d is invalid", block.Header.Height)
		}
	})
}

// Tests that the node contains the expected block range.
func TestBlock_Range(t *testing.T) {
	testNode(t, func(t *testing.T, node e2e.Node) {
		// We do not run this test on seed nodes or nodes with data
		// companion-related pruning enabled.
		if node.Mode == e2e.ModeSeed || node.EnableCompanionPruning {
			return
		}

		client, err := node.Client()
		require.NoError(t, err)
		status, err := client.Status(ctx)
		require.NoError(t, err)

		first := status.SyncInfo.EarliestBlockHeight
		last := status.SyncInfo.LatestBlockHeight

		switch {
		case node.StateSync:
			assert.Greater(t, first, node.Testnet.InitialHeight,
				"state synced nodes should not contain network's initial height")

		case node.RetainBlocks > 0 && int64(node.RetainBlocks) < (last-node.Testnet.InitialHeight+1):
			// Delta handles race conditions in reading first/last heights.
			// The pruning mechanism is now asynchronous and might have been woken up yet to complete the pruning
			// So we have no guarantees that all the blocks will have been pruned by the time we check
			// Thus we allow for some flexibility in the difference between the expected retain blocks number
			// and the actual retain blocks (which should be greater)
			assert.InDelta(t, node.RetainBlocks, last-first+1, 10,
				"node not pruning expected blocks")
			assert.GreaterOrEqual(t, uint64(last-first+1), node.RetainBlocks, "node pruned more blocks than it should")

		default:
			assert.Equal(t, node.Testnet.InitialHeight, first,
				"node's first block should be network's initial height")
		}

		for h := first; h <= last; h++ {
			resp, err := client.Block(ctx, &(h))
			if err != nil && node.RetainBlocks > 0 && h == first {
				// Ignore errors in first block if node is pruning blocks due to race conditions.
				continue
			}
			require.NoError(t, err)
			assert.Equal(t, h, resp.Block.Height)
		}

		for h := node.Testnet.InitialHeight; h < first; h++ {
			_, err := client.Block(ctx, &(h))
			require.Error(t, err)
		}
	})
}