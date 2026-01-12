package main
func sum(items []int) int {
	total := 0
	for _, x := range items {
		total += x
	}
	return total
}
