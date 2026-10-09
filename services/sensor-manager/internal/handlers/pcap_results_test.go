package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// The pcap-processor's result callback carries how much of the capture its
// snapshot length cut off. The upload page reads it back to explain a job that
// completed with less than the capture seemed to hold, so the handler must
// pass it through to the store.

func postPcapResults(t *testing.T, store *stubPcapService, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := &Handler{pcapService: store, log: logrus.New()}
	r.POST("/internal/pcap/jobs/:id/results", h.UpdatePcapJobResults)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/internal/pcap/jobs/"+uuid.NewString()+"/results", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func TestUpdatePcapJobResults_RecordsTruncation(t *testing.T) {
	store := &stubPcapService{}
	w := postPcapResults(t, store, `{"status":"completed","discovery_count":9,"packet_count":22572,
		"protocols_found":{"QUIC":4,"HOST":1},"truncated_packet_count":17972,"snapshot_length":128}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if store.updates["truncated_packet_count"] != int64(17972) {
		t.Errorf("truncated_packet_count = %v, want 17972", store.updates["truncated_packet_count"])
	}
	if store.updates["snapshot_length"] != 128 {
		t.Errorf("snapshot_length = %v, want 128", store.updates["snapshot_length"])
	}
}

// An unknown snapshot length arrives as 0 and must not be stored as a capture
// that keeps zero bytes per packet.
func TestUpdatePcapJobResults_UnknownSnapshotLengthIsNotStored(t *testing.T) {
	store := &stubPcapService{}
	w := postPcapResults(t, store, `{"status":"completed","truncated_packet_count":0,"snapshot_length":0}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	if _, ok := store.updates["snapshot_length"]; ok {
		t.Errorf("snapshot_length 0 was stored: %v", store.updates["snapshot_length"])
	}
	if store.updates["truncated_packet_count"] != int64(0) {
		t.Errorf("truncated_packet_count = %v, want 0", store.updates["truncated_packet_count"])
	}
}
