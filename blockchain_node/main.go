package main

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed dashboard.html
var defaultDashboardHTML []byte

// Transaction represents a threat domain or IP payload stored on-chain
type Transaction struct {
	TxID       string  `json:"txId"`
	Domain     string  `json:"domain"`
	IP         string  `json:"ip"`
	Category   string  `json:"category"`
	RiskScore  float64 `json:"riskScore"`
	ReportedBy string  `json:"reportedBy"`
	Timestamp  int64   `json:"timestamp"`
	Signature  string  `json:"signature"`
}

// Block represents a single block in the Angad Blockchain
type Block struct {
	Index        int           `json:"index"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Miner        string        `json:"miner"`
	MerkleRoot   string        `json:"merkleRoot"`
	PrevHash     string        `json:"prevHash"`
	Hash         string        `json:"hash"`
	Nonce        int           `json:"nonce"`
	Difficulty   int           `json:"difficulty"`
}

// Blockchain holds the chain of blocks and state
type Blockchain struct {
	Blocks        []Block
	Mempool       []Transaction
	Difficulty    int
	DomainIndex   map[string]Block
	IPIndex       map[string]Block
	mu            sync.RWMutex
	TotalTx       int
	StartTime     time.Time
}

var chain = &Blockchain{
	Difficulty:  2, // Initial Proof-of-Work prefix zeros
	DomainIndex: make(map[string]Block),
	IPIndex:     make(map[string]Block),
	StartTime:   time.Now(),
}

// Rate Limiting
type visitor struct {
	count    int
	lastSeen time.Time
}

var (
	visitors = make(map[string]*visitor)
	muRate   sync.Mutex
)

func rateLimit(ip string) bool {
	muRate.Lock()
	defer muRate.Unlock()
	v, exists := visitors[ip]
	if !exists {
		visitors[ip] = &visitor{1, time.Now()}
		return true
	}
	if time.Since(v.lastSeen) > time.Minute {
		v.count = 1
		v.lastSeen = time.Now()
		return true
	}
	v.count++
	return v.count <= 10
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func computeTxID(tx *Transaction) string {
	data := fmt.Sprintf("%s:%s:%s:%f:%s:%d", tx.Domain, tx.IP, tx.Category, tx.RiskScore, tx.ReportedBy, tx.Timestamp)
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func generateSignature(tx *Transaction) string {
	secret := "angad-secret-key"
	data := fmt.Sprintf("%s:%s:%s:%f:%s:%d", tx.Domain, tx.IP, tx.Category, tx.RiskScore, tx.ReportedBy, tx.Timestamp)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func computeMerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return ""
	}
	var hashes []string
	for _, tx := range txs {
		hashes = append(hashes, tx.TxID)
	}
	return merkleRec(hashes)
}

func merkleRec(hashes []string) string {
	if len(hashes) == 1 {
		return hashes[0]
	}
	var nextLevel []string
	for i := 0; i < len(hashes); i += 2 {
		h1 := hashes[i]
		h2 := h1
		if i+1 < len(hashes) {
			h2 = hashes[i+1]
		}
		hash := sha256.Sum256([]byte(h1 + h2))
		nextLevel = append(nextLevel, hex.EncodeToString(hash[:]))
	}
	return merkleRec(nextLevel)
}

func CalculateHash(b Block) string {
	txBytes, _ := json.Marshal(b.Transactions)
	record := fmt.Sprintf("%d%d%s%s%s%s%d%d", b.Index, b.Timestamp, string(txBytes), b.Miner, b.MerkleRoot, b.PrevHash, b.Nonce, b.Difficulty)
	h := sha256.New()
	h.Write([]byte(record))
	return hex.EncodeToString(h.Sum(nil))
}

func (bc *Blockchain) InitGenesisBlock() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if len(bc.Blocks) > 0 {
		return
	}

	tx := Transaction{
		Domain:     "genesis.angad.network",
		Category:   "safe",
		RiskScore:  0.0,
		ReportedBy: "SYSTEM",
		Timestamp:  time.Now().Unix(),
	}
	tx.TxID = computeTxID(&tx)
	tx.Signature = generateSignature(&tx)

	genesis := Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: []Transaction{tx},
		Miner:        "SYSTEM",
		PrevHash:     "0000000000000000000000000000000000000000000000000000000000000000",
		Difficulty:   bc.Difficulty,
		Nonce:        0,
	}
	genesis.MerkleRoot = computeMerkleRoot(genesis.Transactions)
	genesis.Hash = CalculateHash(genesis)

	bc.Blocks = append(bc.Blocks, genesis)
	bc.DomainIndex[tx.Domain] = genesis
	if tx.IP != "" {
		bc.IPIndex[tx.IP] = genesis
	}
	bc.TotalTx++
	bc.saveToFile()
}

func (bc *Blockchain) adjustDifficulty() {
	if len(bc.Blocks)%10 == 0 && len(bc.Blocks) > 0 {
		lastBlock := bc.Blocks[len(bc.Blocks)-1]
		block10Ago := bc.Blocks[len(bc.Blocks)-10]
		timeDiff := lastBlock.Timestamp - block10Ago.Timestamp
		expectedTime := int64(10 * 30) // 30 seconds per block
		if timeDiff < expectedTime/2 {
			bc.Difficulty++
		} else if timeDiff > expectedTime*2 {
			bc.Difficulty--
		}
		if bc.Difficulty < 1 {
			bc.Difficulty = 1
		}
	}
}

func (bc *Blockchain) MineBlock(miner string) Block {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	txs := bc.Mempool
	bc.Mempool = []Transaction{}

	bc.adjustDifficulty()

	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := Block{
		Index:        prevBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		Transactions: txs,
		Miner:        miner,
		PrevHash:     prevBlock.Hash,
		Difficulty:   bc.Difficulty,
		Nonce:        0,
	}
	newBlock.MerkleRoot = computeMerkleRoot(newBlock.Transactions)

	target := strings.Repeat("0", bc.Difficulty)
	for {
		newBlock.Hash = CalculateHash(newBlock)
		if strings.HasPrefix(newBlock.Hash, target) {
			break
		}
		newBlock.Nonce++
	}

	bc.Blocks = append(bc.Blocks, newBlock)
	for _, tx := range txs {
		if tx.Domain != "" {
			bc.DomainIndex[tx.Domain] = newBlock
		}
		if tx.IP != "" {
			bc.IPIndex[tx.IP] = newBlock
		}
		bc.TotalTx++
	}
	bc.saveToFile()
	return newBlock
}

func getChainFilePath() string {
	if p := os.Getenv("CHAIN_FILE"); p != "" {
		return p
	}
	return "chain.json"
}

func (bc *Blockchain) saveToFile() {
	filePath := getChainFilePath()
	if dir := filepath.Dir(filePath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	data, err := json.MarshalIndent(bc.Blocks, "", "  ")
	if err == nil {
		_ = os.WriteFile(filePath, data, 0644)
	}
}

func (bc *Blockchain) loadFromFile() bool {
	filePath := getChainFilePath()
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	var blocks []Block
	if err := json.Unmarshal(data, &blocks); err != nil {
		return false
	}
	if len(blocks) > 0 {
		bc.mu.Lock()
		defer bc.mu.Unlock()
		bc.Blocks = blocks
		bc.Difficulty = blocks[len(blocks)-1].Difficulty
		bc.DomainIndex = make(map[string]Block)
		bc.IPIndex = make(map[string]Block)
		bc.TotalTx = 0
		for _, b := range blocks {
			for _, tx := range b.Transactions {
				if tx.Domain != "" {
					bc.DomainIndex[tx.Domain] = b
				}
				if tx.IP != "" {
					bc.IPIndex[tx.IP] = b
				}
				bc.TotalTx++
			}
		}
		return true
	}
	return false
}

func (bc *Blockchain) ValidateChain() (bool, string) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for i := 1; i < len(bc.Blocks); i++ {
		current := bc.Blocks[i]
		prev := bc.Blocks[i-1]

		if current.Hash != CalculateHash(current) {
			return false, fmt.Sprintf("Invalid hash at block %d", i)
		}
		if current.PrevHash != prev.Hash {
			return false, fmt.Sprintf("Invalid previous hash at block %d", i)
		}
		target := strings.Repeat("0", current.Difficulty)
		if !strings.HasPrefix(current.Hash, target) {
			return false, fmt.Sprintf("Hash does not meet difficulty at block %d", i)
		}
		if current.MerkleRoot != computeMerkleRoot(current.Transactions) {
			return false, fmt.Sprintf("Invalid Merkle root at block %d", i)
		}
	}
	return true, "Chain is valid"
}

func validateTransaction(tx *Transaction) error {
	if tx.Domain == "" && tx.IP == "" {
		return fmt.Errorf("domain or ip must be provided")
	}
	if len(tx.Domain) > 253 {
		return fmt.Errorf("invalid domain length")
	}
	validCategories := map[string]bool{"safe": true, "phishing": true, "malware": true, "data_leak": true, "scam": true, "botnet": true}
	if !validCategories[tx.Category] {
		return fmt.Errorf("invalid category")
	}
	if tx.RiskScore < 0.0 || tx.RiskScore > 1.0 {
		return fmt.Errorf("invalid risk score")
	}
	if tx.ReportedBy == "" {
		return fmt.Errorf("reportedBy cannot be empty")
	}
	return nil
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}
	return ip
}

func main() {
	if !chain.loadFromFile() {
		chain.InitGenesisBlock()
	}

	// GET / (Serve Web Dashboard Explorer)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/dashboard" {
			http.NotFound(w, r)
			return
		}
		// Try reading disk first for instant updates
		if content, err := os.ReadFile("dashboard.html"); err == nil && len(content) > 0 {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(content)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(defaultDashboardHTML)
	})

	// GET /health
	http.HandleFunc("/health", withCORS(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "healthy", "uptime": time.Since(chain.StartTime).Seconds()})
	}))

	// GET /chain
	http.HandleFunc("/chain", withCORS(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chain.mu.RLock()
		defer chain.mu.RUnlock()

		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		if fromStr == "" && toStr == "" {
			json.NewEncoder(w).Encode(chain.Blocks)
			return
		}

		from, _ := strconv.Atoi(fromStr)
		to, _ := strconv.Atoi(toStr)

		if to == 0 || to > len(chain.Blocks) {
			to = len(chain.Blocks)
		}
		if from < 0 {
			from = 0
		}
		if from > to {
			from = to
		}

		json.NewEncoder(w).Encode(chain.Blocks[from:to])
	}))

	// GET /stats
	http.HandleFunc("/stats", withCORS(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chain.mu.RLock()
		defer chain.mu.RUnlock()
		
		chainBytes, _ := json.Marshal(chain.Blocks)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"blockCount":      len(chain.Blocks),
			"totalTx":         chain.TotalTx,
			"mempoolSize":     len(chain.Mempool),
			"difficulty":      chain.Difficulty,
			"chainSizeBytes":  len(chainBytes),
			"uptimeSeconds":   time.Since(chain.StartTime).Seconds(),
		})
	}))

	// GET /validate
	http.HandleFunc("/validate", withCORS(func(w http.ResponseWriter, r *http.Request) {
		valid, msg := chain.ValidateChain()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": valid, "message": msg})
	}))

	// GET /verify
	http.HandleFunc("/verify", withCORS(func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		ip := r.URL.Query().Get("ip")
		w.Header().Set("Content-Type", "application/json")

		chain.mu.RLock()
		var b Block
		var found bool
		if domain != "" {
			b, found = chain.DomainIndex[domain]
		}
		if !found && ip != "" {
			b, found = chain.IPIndex[ip]
		}
		chain.mu.RUnlock()

		if found {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"found":  true,
				"block":  b,
				"status": "blacklisted_on_blockchain",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"found":  false,
				"status": "clean",
			})
		}
	}))

	// POST /tx
	http.HandleFunc("/tx", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !rateLimit(getIP(r)) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		var tx Transaction
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := validateTransaction(&tx); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		tx.Timestamp = time.Now().Unix()
		tx.TxID = computeTxID(&tx)
		tx.Signature = generateSignature(&tx)

		chain.mu.Lock()
		chain.Mempool = append(chain.Mempool, tx)
		chain.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "added_to_mempool",
			"txId":   tx.TxID,
		})
	}))

	// POST /mine
	http.HandleFunc("/mine", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !rateLimit(getIP(r)) {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Backward compatibility: If body contains a transaction, add it to mempool first
		if r.ContentLength > 0 {
			var tx Transaction
			if err := json.NewDecoder(r.Body).Decode(&tx); err == nil {
				if err := validateTransaction(&tx); err == nil {
					tx.Timestamp = time.Now().Unix()
					tx.TxID = computeTxID(&tx)
					tx.Signature = generateSignature(&tx)
					chain.mu.Lock()
					chain.Mempool = append(chain.Mempool, tx)
					chain.mu.Unlock()
				}
			}
		}

		minedBlock := chain.MineBlock("Miner-Node-1")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "mined",
			"block":  minedBlock,
		})
	}))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if !strings.Contains(port, ":") {
		port = ":" + port
	}
	fmt.Printf("[Angad Go Blockchain Node] Running on http://0.0.0.0%s\n", port)
	log.Fatal(http.ListenAndServe(port, nil))
}
