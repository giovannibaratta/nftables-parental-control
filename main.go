package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"nftables-parental-control/logic"
	"os"
)

type BlockRequest struct {
	MacAddress string `json:"mac_address"`
}

func main() {

	port := os.Getenv("NFT_PC_PORT")
	if port == "" {
		port = "8080"
	}

	// Create a new HTTP router
	router := http.NewServeMux()

	router.HandleFunc("/block-client", handleBlockRequest)

	fmt.Printf("Server listening on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

func handleBlockRequest(w http.ResponseWriter, r *http.Request) {
	// Decode the JSON request body
	var req BlockRequest
	err := json.NewDecoder(r.Body).Decode(&req)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = logic.BlockMacAddress(req.MacAddress)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
