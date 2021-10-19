package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var endpointsExecTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name: "endpoint_exec_time",
        Help: "The total endpoint execution time.",
    },
    []string{
        "path",
    })

type logWriter struct {
	http.ResponseWriter

	statusCode int
	response   bytes.Buffer
}

func (w *logWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.statusCode = status
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.response.Write(p)
	return w.ResponseWriter.Write(p)
}

func logRequest(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		writer := &logWriter{
			ResponseWriter: rw,
		}

		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println("Could not read request body", err)
			handleError(errors.New("could not read request"), rw)
			return
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		started := time.Now()
		h(writer, r)
		done := time.Since(started)

        endpointsExecTime.With(prometheus.Labels{"path": r.URL.Path}).Observe(float64(done))

		log.Printf(
			"PATH: %s -> %d. Finished in %v.\n\tParams: %s\n\tResponse: %s",
			r.URL.Path,
			writer.statusCode,
			done,
			string(body),
			writer.response.String(),
		)
	}
}
