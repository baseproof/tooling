// Package federation is the agnostic operational layer for multi-network
// CONSORTIUM governance over the baseproof SDK. It provides:
//
//   - FormConsortium — provision a consortium governance log (formation.go);
//   - membership — propose / collect / execute / activate member add & remove
//     scope amendments over the lifecycle layer (membership.go);
//   - MappingEscrowManager — threshold-escrow (Pedersen-VSS) mapping of a
//     vendor identity to its real DID, with on-log commitment (mapping_escrow.go).
//
// It is payload-blind and domain-free: judicial, AI-agentic, or any other network
// type drives it through the same vocabulary (member DIDs, authority sets,
// settlement units), supplying only its own names — no court/case/jurisdiction
// concepts live here.
package federation
