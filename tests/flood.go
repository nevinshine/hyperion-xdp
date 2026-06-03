package main

import (
	"fmt"
	"net"
	"os"
	"sync"
)

func main() {
	target := "127.0.0.1:53"
	if len(os.Args) > 1 {
		target = os.Args[1] + ":53"
	}
	addr, _ := net.ResolveUDPAddr("udp", target)
	payload := make([]byte, 1024)
	
	var wg sync.WaitGroup
	// Spawn 50 rapid-fire UDP producers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, _ := net.DialUDP("udp", nil, addr)
			defer conn.Close()
			for j := 0; j < 50000; j++ {
				conn.Write(payload)
			}
		}()
	}
	
	fmt.Println("Blasting...")
	wg.Wait()
	fmt.Println("Done")
}
