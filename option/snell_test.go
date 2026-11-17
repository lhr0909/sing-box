package option

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
)

func TestSnellOutboundVersions(t *testing.T) {
	for _, version := range []int{2, 3, 4, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			extra := `,"obfs_mode":"tls","obfs_host":"example.com"`
			if version == 6 {
				extra = `,"mode":"unshaped"`
			}
			content := []byte(fmt.Sprintf(`{"version":%d,"server":"127.0.0.1","server_port":10000,"psk":"test-password"%s}`, version, extra))
			var options SnellOutboundOptions
			if err := json.Unmarshal(content, &options); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(options)
			if err != nil {
				t.Fatal(err)
			}
			var decoded SnellOutboundOptions
			if err = json.Unmarshal(encoded, &decoded); err != nil || !reflect.DeepEqual(options, decoded) {
				t.Fatalf("round trip: %+v %v", decoded, err)
			}
		})
	}
	for _, content := range []string{`{}`, `{"version":1}`, `{"version":5}`, `{"version":7}`, `{"version":3,"mode":"unshaped"}`, `{"version":6,"obfs_mode":"tls"}`} {
		var options SnellOutboundOptions
		if err := json.Unmarshal([]byte(content), &options); err == nil {
			t.Fatalf("accepted %s", content)
		}
	}
	for _, version := range []int{0, 1, 5, 7} {
		if _, err := json.Marshal(SnellOutboundOptions{Version: version}); err == nil {
			t.Fatalf("marshaled version %d", version)
		}
	}
	// This change does not enable legacy server/inbound versions.
	for _, version := range []int{2, 3, 4} {
		var options SnellInboundOptions
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"version":%d}`, version)), &options); err == nil {
			t.Fatalf("accepted inbound version %d", version)
		}
	}
}

func TestSnellOutboundSchema(t *testing.T) {
	content, err := schema.Generate(context.Background(), reflect.TypeFor[SnellOutboundOptions]())
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		OneOf []struct{ Properties map[string]stdjson.RawMessage }
	}
	if err = stdjson.Unmarshal(content, &root); err != nil {
		t.Fatal(err)
	}
	if len(root.OneOf) != 4 {
		t.Fatalf("variants: %s", content)
	}
	for i, version := range []int{2, 3, 4, 6} {
		var discriminator struct{ Const int }
		stdjson.Unmarshal(root.OneOf[i].Properties["version"], &discriminator)
		if discriminator.Const != version {
			t.Fatalf("variant %d: %+v", i, discriminator)
		}
		_, obfs := root.OneOf[i].Properties["obfs_mode"]
		_, mode := root.OneOf[i].Properties["mode"]
		if obfs != (version != 6) || mode != (version == 6) {
			t.Fatalf("incorrect version-specific schema %d", version)
		}
	}
}
