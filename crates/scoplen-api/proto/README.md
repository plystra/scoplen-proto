# Internal protobuf contracts

The `spl.gateway.v1.Control` and `spl.agent.v1.Agent` definitions are authored
from `scoplen-docs/09-gateway-and-host-agent.md`. They are source contracts for
the internal mTLS gRPC channels; no client or server repository may invent a
parallel message shape.

All opaque byte fields and repeated collections carry the documented maximum in
the field comment. Runtime implementations must enforce those limits before
allocation and must authenticate the mTLS peer before accepting a request.

Generated Rust and TypeScript bindings, descriptor publishing, and concrete
tonic service implementations remain separate work after the source contract
is reviewed.
