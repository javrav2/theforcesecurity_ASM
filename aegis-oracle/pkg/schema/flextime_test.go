package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFlexTimeUnmarshalNaiveISO(t *testing.T) {
	var got FlexTime
	if err := json.Unmarshal([]byte(`"2026-07-22T18:01:51.446024"`), &got); err != nil {
		t.Fatalf("unmarshal naive ISO: %v", err)
	}
	want := time.Date(2026, 7, 22, 18, 1, 51, 446024000, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got.Time, want)
	}
}

func TestFlexTimeUnmarshalRFC3339Z(t *testing.T) {
	var got FlexTime
	if err := json.Unmarshal([]byte(`"2026-07-22T18:01:51.446024Z"`), &got); err != nil {
		t.Fatalf("unmarshal Z: %v", err)
	}
	want := time.Date(2026, 7, 22, 18, 1, 51, 446024000, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got.Time, want)
	}
}

func TestFlexTimeUnmarshalNull(t *testing.T) {
	var got FlexTime
	if err := json.Unmarshal([]byte(`null`), &got); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("expected zero time, got %v", got.Time)
	}
}
