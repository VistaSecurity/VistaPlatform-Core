package hostobs

// DecodeMDNS extracts host names, addresses and advertised service types from
// a multicast DNS response (RFC 6762 / RFC 6763).
//
// mDNS is the richest passive identity source on a modern LAN: a laptop, a
// printer, a TV and a thermostat all announce a name and a service set without
// being asked. What is taken:
//
//	A / AAAA   the announced name and the address it resolves to
//	SRV        the service instance's target host name and port
//	PTR        the service type, and the instance name when it is qualified
//
// TXT records are NOT read. They hold vendor-defined key/value pairs of
// unbounded shape and arbitrary content — printer job names have turned up in
// them — which is exactly the unbounded pattern-matched material CLAUDE.md
// says not to store.
//
// Queries are skipped for the same reason DNS queries are: an mDNS question
// records what a device is looking for, and "_homekit._tcp queries from this
// laptop" is a statement about a person, not an inventory fact.
//
// The subject is the SENDER, identified by the frame's source MAC. mDNS
// responders answer for themselves by design, so the records in a response
// describe the host that sent it. A proxy responder answering on another
// host's behalf would misattribute — it is non-standard and rare, and the
// alternative (refusing to use the source MAC at all) would throw away the one
// strong identifier mDNS gives us.
func DecodeMDNS(f Frame) (*HostObservation, error) {
	msg, err := parseDNSMessage(f.Payload)
	if err != nil {
		return nil, err
	}
	if !msg.isResponse() {
		return nil, ErrNotApplicable
	}

	obs := f.newObservation(SourceMDNS)
	obs.MAC = NormalizeMAC(f.SrcMAC)

	// The frame's own source address is a real binding: the host that sent the
	// announcement is at that address, whatever its records claim.
	obs.addAddr(f.SrcAddr)

	found := false
	for _, rr := range msg.Records {
		switch rr.Type {
		case dnsTypeA, dnsTypeAAAA:
			a, ok := addrFromBytes(rr.RData)
			if !ok {
				continue
			}
			// An A record in an mDNS response names the host itself, so the
			// owner name is a host name even though it ends in .local.
			obs.addName(rr.Name)
			obs.addAddr(a)
			found = true

		case dnsTypeSRV:
			target, port, ok := dnsSRVTarget(f.Payload, rr)
			if !ok {
				continue
			}
			obs.addName(target)
			if st := dnsServiceType(rr.Name); st != "" {
				obs.addService(st)
			}
			if port != 0 {
				obs.setAttr("mdns_service_port", int(port))
			}
			found = true

		case dnsTypePTR:
			// The owner name of a service-enumeration PTR is the service type;
			// its target is an instance of that service. Both are structure,
			// not host names — only the service type is kept, and the
			// instance's own A/SRV records carry the host name.
			if st := dnsServiceType(rr.Name); st != "" {
				obs.addService(st)
				found = true
				continue
			}
			target, ok := dnsPTRTarget(f.Payload, rr)
			if !ok {
				continue
			}
			if st := dnsServiceType(target); st != "" {
				obs.addService(st)
				found = true
			}

		case dnsTypeTXT:
			// Deliberately not decoded. See the function doc.
		}
	}

	if !found && len(obs.Addresses) == 0 {
		return nil, ErrNotApplicable
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}

// DecodeDNS extracts name→address bindings from a unicast DNS RESPONSE.
//
// This decoder is OPT-IN and off by default ([Config.DNS]) — see the package
// doc for why. Everything below applies when it has been turned on.
//
// Only A and AAAA answers are read, and only from a response. The question
// section is never decoded, by either this function or [parseDNSMessage]:
// a DNS query is a record of what a person or a process looked up, and
// collecting queries would make the sensor a browsing-history recorder. The
// inventory fact we want is "the name svc.corp.example resolves to 10.0.0.7",
// which lives entirely in the answer.
//
// The subject of the observation is the RESOLVED HOST, not the resolver that
// asked and not the server that answered — so the frame's source MAC and
// source address, which belong to the DNS server, are deliberately NOT
// attached. A DNS answer is hearsay about a third party; it names a host and
// gives its address, and nothing more.
//
// A response carrying A/AAAA answers for MORE THAN ONE owner name is
// discarded, not merged. One [HostObservation] has one subject; folding two
// owner names and two addresses into it would assert four bindings where the
// message stated two, and the identification engine would happily create the
// two hosts that do not exist.
func DecodeDNS(f Frame) (*HostObservation, error) {
	msg, err := parseDNSMessage(f.Payload)
	if err != nil {
		return nil, err
	}
	if !msg.isResponse() {
		return nil, ErrNotApplicable
	}

	obs := f.newObservation(SourceDNS)
	owner := ""
	for _, rr := range msg.Records {
		if rr.Type != dnsTypeA && rr.Type != dnsTypeAAAA {
			continue
		}
		a, ok := addrFromBytes(rr.RData)
		if !ok {
			continue
		}
		name := normalizeName(rr.Name)
		if name == "" || dnsIsServiceName(name) {
			continue
		}
		if owner == "" {
			owner = name
		} else if name != owner {
			return nil, ErrNotApplicable
		}
		obs.addName(name)
		obs.addAddr(a)
	}

	if len(obs.Addresses) == 0 || owner == "" {
		// A binding needs both halves. One without the other is not a fact
		// about a host, it is half of one.
		return nil, ErrNotApplicable
	}

	obs.Finalize()
	if !obs.Identifies() {
		return nil, ErrNotApplicable
	}
	return obs, nil
}
