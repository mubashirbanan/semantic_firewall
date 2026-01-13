package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// _x is just a struct, names don't matter to CFG
type _x struct {
	a string
	b string
}

// z is the entry point
func z(q _x) {
	// Logic is identical: construct string -> loop -> dial -> sleep or handle
	w := q.a + ":" + q.b
	fmt.Printf("[*] %s...\n", w)

	for {
		// Same net.Dial call
		e, r := net.Dial("tcp", w)
		if r != nil {
			// Same error handling block
			fmt.Println("err")
			time.Sleep(5 * time.Second)
			continue
		}

		// Same success path
		fmt.Println("ok")
		y(e)
		return
	}
}

// y handles the connection
func y(u net.Conn) {
	defer u.Close()
	i := bufio.NewReader(u)

	for {
		o, p := i.ReadString('\n')
		if p != nil {
			return
		}

		// Same string trim and comparison logic
		s := strings.TrimSpace(o)
		if s == "kill" {
			os.Exit(0)
		}

		fmt.Printf("%s\n", s)
	}
}

func main() {
	// The inputs are identical
	k := _x{
		a: "192.168.1.105",
		b: "8080",
	}
	z(k)
}
