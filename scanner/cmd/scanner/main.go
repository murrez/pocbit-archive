package main

import (
	"fmt"
	"os"
	"os/exec"
)

// Configuration
const masscanOutput = "masscan_results_telnet.txt" // Output file to store scan results

var targetRanges = []string{
	"110.0.0.0/8",  // Full range of 110.x.x.x
	"75.0.0.0/8",   // Full range of 75.x.x.x
	"222.0.0.0/8",  // Full range of 222.x.x.x
	"213.0.0.0/8",  // Full range of 213.x.x.x
	"191.0.0.0/8",  // Full range of 191.x.x.x
	"200.0.0.0/8",  // Full range of 200.x.x.x
	"179.0.0.0/8",  // Full range of 179.x.x.x
	"189.0.0.0/8",  // Full range of 189.x.x.x
	"152.0.0.0/8",  // Full range of 152.x.x.x
	"87.0.0.0/8",   // Full range of 87.x.x.x
	"176.0.0.0/8",  // Full range of 176.x.x.x
	"49.0.0.0/8",   // Full range of 49.x.x.x
	"90.0.0.0/8",   // Full range of 90.x.x.x
	"15.0.0.0/8",   // Full range of 15.x.x.x
	"193.0.0.0/8",  // Full range of 193.x.x.x
	"20.0.0.0/8",   // Full range of 20.x.x.x
	"91.0.0.0/8",   // Full range of 91.x.x.x
	"85.0.0.0/8",   // Full range of 85.x.x.x
	"38.0.0.0/8",   // Full range of 38.x.x.x
	"82.0.0.0/8",   // Full range of 82.x.x.x
	"187.0.0.0/8",  // Full range of 187.x.x.x
	"100.0.0.0/8",  // Full range of 100.x.x.x
	"186.0.0.0/8",  // Full range of 186.x.x.x
	"104.0.0.0/8",  // Full range of 104.x.x.x
	"39.0.0.0/8",   // Full range of 39.x.x.x
	"119.0.0.0/8",  // Full range of 119.x.x.x
	"96.0.0.0/8",   // Full range of 96.x.x.x
}

// scanNetwork scans the target network ranges for open port 23 (Telnet)
// using Masscan. The results are written to a file.
func scanNetwork() {
	fmt.Println("[*] Scanning network for Telnet devices (port 23)...")

	for _, targetRange := range targetRanges {
		fmt.Printf("[*] Scanning range: %s\n", targetRange)

		cmd := exec.Command("masscan", "-p23", "--rate=5000", targetRange, "-oL", masscanOutput, "--append-output")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error occurred while scanning range %s: %v\n", targetRange, err)
			continue
		}
		fmt.Printf("[*] Scan complete for range: %s\n", targetRange)
	}

	fmt.Printf("[*] All scans complete. Results saved to %s\n", masscanOutput)
}

func main() {
	scanNetwork()
}
