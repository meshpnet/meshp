package session

import (
	"context"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// rawDial performs the handshake by hand so a rejection can be observed directly.
//
// The real client signs with its own key and reconnects on failure, neither of which
// suits a test that wants to send a deliberately wrong hello exactly once and see what
// the server does with it.
//
// A nil return means the server accepted the session: it answered with ServerHello. A
// non-nil return means it closed the connection instead.
func rawDial(ctx context.Context, baseURL string, membershipID uuid.UUID, identityKey, challenge, signature []byte) error {
	wsURL := strings.Replace(baseURL, "http://", "ws://", 1) + "/api/v1/session"

	dialCtx, cancelDial := context.WithTimeout(ctx, 10*time.Second)
	defer cancelDial()
	conn, upgradeResp, err := websocket.Dial(dialCtx, wsURL, nil)
	if upgradeResp != nil && upgradeResp.Body != nil {
		_ = upgradeResp.Body.Close()
	}
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseNow() }()

	hello := &meshpv1.ClientMessage{
		Payload: &meshpv1.ClientMessage_Hello{Hello: &meshpv1.ClientHello{
			IdentityPublicKey:  identityKey,
			Challenge:          challenge,
			ChallengeSignature: signature,
			MembershipId:       membershipID.String(),
			AgentVersion:       "raw-test",
		}},
	}
	data, err := proto.Marshal(hello)
	if err != nil {
		return err
	}

	writeCtx, cancelWrite := context.WithTimeout(ctx, 10*time.Second)
	defer cancelWrite()
	if err := conn.Write(writeCtx, websocket.MessageBinary, data); err != nil {
		return err
	}

	readCtx, cancelRead := context.WithTimeout(ctx, 10*time.Second)
	defer cancelRead()
	_, _, err = conn.Read(readCtx)
	return err
}
