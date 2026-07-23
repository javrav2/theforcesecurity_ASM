package schema

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// FlexTime is time.Time that accepts RFC-3339 with or without a timezone
// suffix on JSON unmarshal. Naive timestamps (common from Python's
// datetime.isoformat() on TIMESTAMP WITHOUT TIME ZONE columns) are treated
// as UTC so ASM → Oracle request decoding does not fail with:
//
//	parsing time "..." as "2006-01-02T15:04:05Z07:00": cannot parse "" as "Z07:00"
type FlexTime struct{ time.Time }

// NewFlexTime wraps a time.Time as FlexTime.
func NewFlexTime(t time.Time) FlexTime {
	return FlexTime{Time: t}
}

func (t FlexTime) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.UTC().Format(time.RFC3339Nano))
}

func (t *FlexTime) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		t.Time = time.Time{}
		return nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			t.Time = parsed.UTC()
			return nil
		}
	}
	return fmt.Errorf("cannot parse time %q", s)
}

func (t *FlexTime) Scan(src any) error {
	switch v := src.(type) {
	case time.Time:
		t.Time = v
		return nil
	case nil:
		t.Time = time.Time{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into FlexTime", src)
	}
}

func (t FlexTime) Value() (driver.Value, error) {
	if t.Time.IsZero() {
		return nil, nil
	}
	return t.Time, nil
}
