package main

import (
	"fmt"
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Printf("BACKEND_RECEIVED method=%s path=%s\n", r.Method, r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend reached\n"))
	})

	if err := http.ListenAndServe(":8081", nil); err != nil {
		panic(err)
	}
}
