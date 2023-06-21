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
var simpleDataWith4Item = []string{
	"a711355f",
	"a77d337f",
	"a7f9365f",
	"a77d397f",
}

var simpleDataWith7Level = []string{
	"010001011232e3e1",
	"010001fd0102a1b1",
	"010001fd010201a2",
	"010001fd0102fde1",
	"010001fdfdfda2b2",
	"010001fdfdffb3d3",
	"0100fe01a432e3e1",
	"0100fefd1232e3ef",
	"01ffcabfa432e3e1",
	"fe011abfb432e3e1",
	"fefd1abfa43ee3e1",
}

var randomSize = flag.Int("randomSize", 1000, "set randomDataItem size")

func TestSimpleVerkleTree(t *testing.T) {
	analysisVerkle(generateItems(simpleDataWith4Item))
}

func TestSparseVerkleTree(t *testing.T) {
	analysisVerkle(generateItems(simpleDataWith7Level))
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

	// if size > 1000, only output max 100 per level
	nodeCache := make(map[int]int)
	for _, item := range input {
		level := getVerkleNodeLevel(root, item.key, 0)
		if len(input) > 1000 && nodeCache[level] > 100 {
			continue
		}
		nodeCache[level] += 1

		//proof, _, _, _, err := MakeVerkleMultiProof(root, [][]byte{item.key}, kv)
		proof, _, _, _, err := MakeVerkleMultiProof(root, [][]byte{item.key})
		if err != nil {
			panic(err)
		}
		serProof, _, err := SerializeProof(proof)
		if err != nil {
			panic(err)
		}
		fmt.Println("key:", hex.EncodeToString(item.key), "level:", level, "proof:", verkleProofCount(serProof))
	}

	storageSize := 0
	export, _ := root.(*InternalNode)
	nodes, err := export.BatchSerialize()
	if err != nil {
		panic(err)
	}

	for _, node := range nodes {
		storageSize += len(node.CommitmentBytes[:])
		storageSize += len(node.SerializedBytes)
	}
	fmt.Println("trieStorageSize:", storageSize)
}

func generateItems(input []string) []Item {
	items := make([]Item, len(input))
	for i, s := range input {
		src := DecodeString(s)
		key := make([]byte, 32)
		if len(src) > len(key) {
			copy(key, src[:32])
		} else {
			copy(key, src)
			for j := len(src); j < len(key); j++ {
				key[j] = 0xff
			}
		}
		items[i] = Item{
			key: key,
			val: valWith32bytes,
		}
	}
	return items
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
