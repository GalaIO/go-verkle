package verkle

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/olekukonko/tablewriter"
	"os"
	"strconv"
	"testing"
)

var valWith32bytes = crypto.Keccak256Hash([]byte("valWith32bytes")).Bytes()

type Item struct {
	key []byte
	val []byte
}

// attention: verkle tree must 32 bytes len
var simpleDataWith4Item = []Item{
	{
		key: DecodeString("a711355fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		val: valWith32bytes,
	},
	{
		key: DecodeString("a77d337fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		val: valWith32bytes,
	},
	{
		key: DecodeString("a7f9365fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		val: valWith32bytes,
	},
	{
		key: DecodeString("a77d397fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		val: valWith32bytes,
	},
}

var randomSize = flag.Int("randomSize", 1000, "set randomDataItem size")

func TestSimpleVerkleTree(t *testing.T) {
	analysisVerkle(simpleDataWith4Item)
}
func TestRandomVerkleTree(t *testing.T) {
	randomDataItem := randomKVList(*randomSize)
	fmt.Println("generated", *randomSize, "kv")
	analysisVerkle(randomDataItem)
}

func analysisVerkle(input []Item) {
	root := New()
	kv := make(map[string][]byte)
	for _, item := range input {
		if err := root.Insert(item.key, item.val, nil); err != nil {
			panic(err)
		}
		kv[string(item.key)] = item.val
	}

	_ = root.Commit()
	for _, item := range input {
		//proof, _, _, _, err := MakeVerkleMultiProof(root, [][]byte{item.key}, kv)
		proof, _, _, _, err := MakeVerkleMultiProof(root, [][]byte{item.key})
		if err != nil {
			panic(err)
		}
		serProof, _, err := SerializeProof(proof)
		if err != nil {
			panic(err)
		}
		level := getVerkleNodeLevel(root, item.key, 0)
		fmt.Println("key:", hex.EncodeToString(item.key), "level:", level, "proof:", verkleProofCount(serProof))
	}

	data := make(map[int][]int)
	scanVerkleTree(root, data, 0)
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Level", "InternalNode", "LeafNode", "Value"})
	for i := 0; i < len(data); i++ {
		d := data[i]
		if len(d) == 0 {
			table.Append([]string{strconv.Itoa(i), "0", "0", "0"})
			continue
		}
		table.Append([]string{strconv.Itoa(i), strconv.Itoa(d[0]), strconv.Itoa(d[1]), strconv.Itoa(d[2])})
	}
	table.Render()
}

var (
	VerkleInterNodeIdx = 0
	VerkleLeafNodeIdx  = 1
	VerkleValueIdx     = 2
)

func scanVerkleTree(src VerkleNode, data map[int][]int, depth int) {
	if data[depth] == nil {
		data[depth] = []int{0, 0, 0}
	}

	switch n := src.(type) {
	case *HashedNode:
		panic("there have hash node")
	case *LeafNode:
		data[depth][VerkleLeafNodeIdx] += 1
		for _, val := range n.Values() {
			if val == nil {
				continue
			}
			data[depth][VerkleValueIdx] += 1
		}
	case *InternalNode:
		data[depth][VerkleInterNodeIdx] += 1
		for _, node := range n.Children() {
			scanVerkleTree(node, data, depth+1)
		}
	default: // It should be an UknonwnNode.
	}
}

func getVerkleNodeLevel(origin VerkleNode, key []byte, depth int) int {
	stem := key[:StemSize]
	switch n := origin.(type) {
	case *LeafNode:
		if equalPaths(n.stem, stem) && n.values[key[StemSize]] != nil {
			return depth
		}
	case *InternalNode:
		for _, child := range n.children {
			level := getVerkleNodeLevel(child, key, depth+1)
			if level > 0 {
				return level
			}
		}
	case *HashedNode:
		panic("got hash node")
	default:
	}

	return -1
}

func verkleProofCount(proof *VerkleProof) int {
	size := len(proof.OtherStems) * 32
	size += len(proof.DepthExtensionPresent)
	size += len(proof.CommitmentsByPath) * 32
	size += len(proof.D)
	size += 17 * 32
	return size
}

func randomKVList(num int) []Item {
	origin := make([]byte, 32)
	_, err := rand.Read(origin)
	if err != nil {
		panic(err)
	}

	ret := make([]Item, num)
	for i := 0; i < num; i++ {
		ret[i] = Item{
			key: crypto.Keccak256Hash(origin, []byte(strconv.Itoa(i))).Bytes(),
			val: valWith32bytes,
		}
	}

	return ret
}

func DecodeString(str string) []byte {
	ret, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return ret
}
