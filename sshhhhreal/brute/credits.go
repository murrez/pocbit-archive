package brute

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

type Credit struct {
	Text string
	Used int
}

var creditMu sync.Mutex

func readCreditsJSON() (credits map[string]map[string]int) {
	data, err := os.ReadFile("credits.json")
	if err != nil {
		return nil
	}

	err = json.Unmarshal(data, &credits)
	if err != nil {
		return nil
	}

	return credits
}

func addUsed(role, name string) {
	creditMu.Lock()
	defer creditMu.Unlock()

	credits := readCreditsJSON()
	credits[role][name]++

	data, _ := json.Marshal(credits)
	os.WriteFile("credits.json", data, 0644)
}

func fetchCredits() (usernames []Credit, passwords []Credit) {
	credits := readCreditsJSON()
	if credits == nil {
		return nil, nil
	}

	for username, used := range credits["username"] {
		usernames = append(usernames, Credit{
			Text: username,
			Used: used,
		})
	}

	sort.Slice(usernames, func(i, j int) bool {
		return usernames[i].Used > usernames[j].Used
	})

	for password, used := range credits["password"] {
		passwords = append(passwords, Credit{
			Text: password,
			Used: used,
		})
	}

	sort.Slice(passwords, func(i, j int) bool {
		return passwords[i].Used > passwords[j].Used
	})

	return usernames, passwords
}
