/**
 * WebRTC ICE candidate filter.
 *
 * Strips local/private IP addresses from ICE candidates to prevent
 * leaking the user's LAN IP to peers. Only allows:
 * - Server-reflexive candidates (srflx) — public IP via STUN
 * - Relay candidates (relay) — via TURN server
 * - mDNS candidates (*.local) — browser-generated, safe
 *
 * Host candidates with real private IPs (192.168.x.x, 10.x.x.x, etc.)
 * are stripped to prevent local network topology leakage.
 */

/** RFC 1918 / RFC 4193 private IP patterns */
const PRIVATE_IP_PATTERNS = [
	/^10\./,
	/^172\.(1[6-9]|2\d|3[01])\./,
	/^192\.168\./,
	/^169\.254\./,       // link-local
	/^fc00:/i,           // IPv6 ULA
	/^fd[0-9a-f]{2}:/i,  // IPv6 ULA
	/^fe80:/i,           // IPv6 link-local
	/^::1$/,             // IPv6 loopback
	/^127\./,            // IPv4 loopback
];

/**
 * Check if an IP address is private/local.
 */
function isPrivateIP(ip: string): boolean {
	return PRIVATE_IP_PATTERNS.some(pattern => pattern.test(ip));
}

/**
 * Extract the IP address from an ICE candidate string.
 * SDP candidate format: "candidate:... <ip> <port> ..."
 */
function extractIP(candidateStr: string): string | null {
	// Standard format: component fields separated by spaces
	// candidate:842163049 1 udp 1677729535 192.168.1.100 44323 typ srflx ...
	const parts = candidateStr.split(' ');
	if (parts.length >= 5) {
		return parts[4]; // IP is the 5th field
	}
	return null;
}

/**
 * Determine the candidate type from an ICE candidate string.
 */
function getCandidateType(candidateStr: string): string | null {
	const match = candidateStr.match(/typ\s+(\w+)/);
	return match ? match[1] : null;
}

/**
 * Filter an ICE candidate. Returns the candidate if safe, null if it should be dropped.
 *
 * Policy:
 * - Allow srflx (STUN-derived public IP) — always safe
 * - Allow relay (TURN) — always safe, IP is the TURN server's
 * - Allow mDNS (*.local) host candidates — browser obfuscates the real IP
 * - Block host candidates with private IPs — leaks LAN topology
 * - Allow host candidates with public IPs — needed for LAN-less setups
 */
export function filterCandidate(candidate: RTCIceCandidate | null): RTCIceCandidate | null {
	if (!candidate || !candidate.candidate) return candidate; // end-of-candidates signal

	const candidateStr = candidate.candidate;
	const type = getCandidateType(candidateStr);
	const ip = extractIP(candidateStr);

	// Always allow relay and srflx
	if (type === 'relay' || type === 'srflx') {
		return candidate;
	}

	// For host candidates, check the IP
	if (type === 'host' && ip) {
		// mDNS candidates (e.g., "a]b1c2d3.local") are safe
		if (ip.endsWith('.local')) {
			return candidate;
		}
		// Block private IPs
		if (isPrivateIP(ip)) {
			console.debug('[ice] Filtered private IP candidate:', ip);
			return null;
		}
	}

	// Allow anything else (prflx, etc.)
	return candidate;
}

/**
 * Wrap a peer connection's onicecandidate handler to filter candidates.
 * Call this after creating the RTCPeerConnection and before setting onicecandidate.
 */
export function wrapIceCandidateHandler(
	pc: RTCPeerConnection,
	handler: (candidate: RTCIceCandidate | null) => void,
): void {
	pc.onicecandidate = (event) => {
		if (!event.candidate) {
			// End of candidates — pass through
			handler(null);
			return;
		}
		const filtered = filterCandidate(event.candidate);
		if (filtered) {
			handler(filtered);
		}
		// else: candidate was stripped, don't forward
	};
}
