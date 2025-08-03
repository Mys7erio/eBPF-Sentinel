package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	// Import your chosen PMML parsing library.
	// "github.com/card-io/gocore"
)

// This struct must match the C struct in eBPF-sentinel.c
type Event struct {
	SrcIP   uint32
	DestIP  uint32
	SrcPort uint16
	DestPort uint16
}

func main() {
	// --- Setup ---
	// Subscribe to signals for graceful shutdown.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// --- Load eBPF Objects (FIXED) ---
	// Load the collection spec from the eBPF object file.
	spec, err := ebpf.LoadCollectionSpec("eBPF-sentinel.o")
	if err != nil {
		log.Fatalf("failed to load eBPF collection spec: %v", err)
	}

	// Define the struct to hold the loaded eBPF objects.
	var objs struct {
		Program      *ebpf.Program `ebpf:"xdp_firewall"`
		DenylistMap  *ebpf.Map     `ebpf:"denylist_map"`
		EventsMap    *ebpf.Map     `ebpf:"events"`
	}

	// Instantiate the collection from the spec.
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load and assign eBPF objects: %v", err)
	}
	defer objs.Program.Close()
	defer objs.DenylistMap.Close()
	defer objs.EventsMap.Close()

	// --- Attach XDP Program ---
	ifaceName := "ens33" // Change this to your network interface.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get interface %s: %v", ifaceName, err)
	}

	// Attach the XDP program to the interface.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Program,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("failed to attach XDP program: %v", err)
	}
	defer l.Close()
	log.Printf("XDP program attached to %s", ifaceName)

	// --- Load ML Model ---
	// Placeholder for loading your PMML model.
	// model, err := YourPMMLParsingLibrary.Load("model.pmml")
	// if err != nil {
	//     log.Fatalf("failed to load ML model: %v", err)
	// }
	log.Println("ML model loaded successfully (placeholder).")

	// --- Process Events ---
	// Create a reader for the ring buffer.
	rd, err := ringbuf.NewReader(objs.EventsMap)
	if err != nil {
		log.Fatalf("failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	go func() {
		log.Println("Waiting for events...")
		for {
			record, err := rd.Read()
			if err != nil {
				// If the stopper channel is closed, the program is shutting down.
				select {
				case <-stopper:
					return
				default:
					log.Printf("error reading from ringbuf: %v", err)
					continue
				}
			}

			var event Event
			// The data from the ring buffer is raw bytes, so we parse it into our Go struct.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("failed to parse event: %v", err)
				continue
			}

			// --- ML Prediction (FIXED) ---
			// Create the feature vector for your model.
			// features := []float64{float64(event.SrcIP), float64(event.DestIP), float64(event.SrcPort), float64(event.DestPort)}

			// In a real implementation, you would use your loaded model here.
			// prediction, err := model.Predict(features)
			// For this example, we'll simulate a "malicious" prediction.
			isMalicious := (event.SrcPort % 100 == 0) // Example logic: block ports ending in 00.
			log.Printf("Received packet: SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d", 
    intToIP(event.SrcIP), intToIP(event.DestIP), event.SrcPort, event.DestPort)
			if isMalicious {
				log.Printf("Malicious activity detected from source IP: %s", intToIP(event.SrcIP))

				// --- Update Denylist Map ---
				// Add the source IP to the denylist map in the kernel.
				// The value '1' is a simple flag.
				err := objs.DenylistMap.Put(event.SrcIP, uint8(1))
				if err != nil {
					log.Printf("failed to update denylist map: %v", err)
				} else {
					log.Printf("IP %s added to denylist.", intToIP(event.SrcIP))
				}
			}
		}
	}()

	// Wait for a shutdown signal.
	<-stopper
	log.Println("Stopper received, exiting.")
}

// Helper function to convert uint32 IP to string.
func intToIP(ip uint32) net.IP {
	// eBPF is little-endian, so we reverse the bytes for the net.IP representation.
	res := make(net.IP, 4)
	binary.BigEndian.PutUint32(res, ip)
	return res
}

