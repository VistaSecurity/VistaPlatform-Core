package smbutil

// DialectName maps SMB2 dialect revision (NEGOTIATE) to a human-readable label.
func DialectName(revision uint16) string {
	switch revision {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	}
	return "SMB 2.x"
}
