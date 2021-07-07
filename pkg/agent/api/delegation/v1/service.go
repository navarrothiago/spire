package delegation

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"

	delegationv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegation/v1"
	types "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/api"
)

// RegisterService registers delegation service on provided server
func RegisterService(s *grpc.Server, service *Service) {
	delegationv1.RegisterDelegationServer(s, service)
}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Config struct {
	//Log             logrus.FieldLogger
	Manager         manager.Manager
	Attestor        attestor.Attestor
	AuthorizedUsers []string
}

func New(config Config) *Service {
	authorizedUsers := map[string]bool{}

	for _, user := range config.AuthorizedUsers {
		authorizedUsers[user] = true
	}

	return &Service{
		manager:         config.Manager,
		attestor:        endpoints.PeerTrackerAttestor{Attestor: config.Attestor},
		authorizedUsers: authorizedUsers,
	}
}

// Service implements the delegation server
type Service struct {
	delegationv1.UnsafeDelegationServer

	manager  manager.Manager
	attestor Attestor

	// Spiffe IDs of users that are authorized to use this API
	authorizedUsers map[string]bool
}

// isCallerAuthorized attests the caller and returns true if its identity is on
// the authorized users map.
func (s *Service) isCallerAuthorized(ctx context.Context) (bool, error) {
	callerSelectors, err := s.attestor.Attest(ctx)
	if err != nil {
		return false, err
	}

	identities := s.manager.MatchingIdentities(callerSelectors)

	for _, identity := range identities {
		id := identity.Entry.SpiffeId

		if _, ok := s.authorizedUsers[id]; ok {
			return true, nil
		}
	}

	return false, nil
}

type chanUpdate struct {
	id     uint64
	update *cache.WorkloadUpdate
}

func (s *Service) FetchX509SVIDs(stream delegationv1.Delegation_FetchX509SVIDsServer) error {
	ctx := stream.Context()
	//log := rpccontext.Logger(ctx)

	authorized, err := s.isCallerAuthorized(ctx)
	if err != nil {
		return fmt.Errorf("failed to attest caller: %w", err)
	}

	if !authorized {
		return status.Error(codes.PermissionDenied, "no authorized")
	}

	notifyChan := make(chan chanUpdate, 1)
	subscribersMap := make(map[uint64]cache.Subscriber)

	var mutex sync.Mutex

	// send empty update to tell everything was fine
	resp := &delegationv1.FetchX509SVIDsResponse{
		Id: 0,
	}

	if err := stream.Send(resp); err != nil {
		//log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	go func() {
		for {
			req, err := stream.Recv()
			if err != nil {
				log.WithError(err).Error("failed to receive from stream")
				return
			}

			switch req.Operation {
			case delegationv1.FetchX509SVIDsRequest_ADD:
				log.Debugf("handling add operation")
				selectors, err := api.SelectorsFromProto(req.Selectors)
				if err != nil {
					log.WithError(err).Error("failed to convert selectors")
					continue
				}

				mutex.Lock()

				subscriber := s.manager.SubscribeToCacheChanges(selectors)
				subscribersMap[req.Id] = subscriber

				// create a new go routime to watch these selectors and notify main channel
				go func() {
					for {
						select {
						case r, ok := <-subscriber.Updates():
							if !ok {
								// channel was closed... just return
								return
							}
							notifyChan <- chanUpdate{
								id:     req.Id,
								update: r,
							}
						case <-ctx.Done():
							return
						}
					}
				}()

				mutex.Unlock()

			case delegationv1.FetchX509SVIDsRequest_DEL:
				log.Debugf("handling del operation")
				subscriber, ok := subscribersMap[req.Id]
				if !ok {
					// TODO: Return error to grpc caller
					log.Debugf("subscriber for ID %d not found", req.Id)
					continue
				}

				// This will close the channel.
				subscriber.Finish()

				mutex.Lock()
				delete(subscribersMap, req.Id)
				mutex.Unlock()
			default:
				// TODO: send error!
			}
		}
	}()

	for {
		select {
		case chanUpdate := <-notifyChan:
			err := s.sendX509SVID(&chanUpdate, stream)
			if err != nil {
				log.WithError(err).Error("failed to write grpc stream")
			}
		case <-ctx.Done():
			return nil
		}

	}
}

func (S *Service) sendX509SVID(chanUpdate *chanUpdate, stream delegationv1.Delegation_FetchX509SVIDsServer) error {
	svids, err := workloadUpdateToProto(chanUpdate.update)
	if err != nil {
		//log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	resp := &delegationv1.FetchX509SVIDsResponse{
		Id:        chanUpdate.id,
		X509Svids: svids,
	}

	if err := stream.Send(resp); err != nil {
		//log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	return nil
}

func workloadUpdateToProto(update *cache.WorkloadUpdate) ([]*delegationv1.X509SVIDWithKey, error) {
	x509Svids := []*delegationv1.X509SVIDWithKey{}

	for _, identity := range update.Identities {
		// Do not send admin nor downstream SVIDs to the caller
		if identity.Entry.Admin || identity.Entry.Downstream {
			continue
		}

		id, _ := idutil.IDProtoFromString(identity.Entry.SpiffeId)

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &delegationv1.X509SVIDWithKey{
			X509Svid: &types.X509SVID{
				Id:        id,
				CertChain: x509util.RawCertsFromCertificates(identity.SVID),
				// TODO: what if SVIDs 0 doesn't exist?
				ExpiresAt: identity.SVID[0].NotAfter.Unix(),
			},
			X509SvidKey: keyData,
			// TODO(Mauricio): federates with
		}

		x509Svids = append(x509Svids, svid)
	}

	return x509Svids, nil
}

func (s *Service) FetchX509Bundles(req *delegationv1.FetchX509BundlesRequest, stream delegationv1.Delegation_FetchX509BundlesServer) error {
	ctx := stream.Context()

	authorized, err := s.isCallerAuthorized(ctx)
	if err != nil {
		return fmt.Errorf("failed to attest caller: %w", err)
	}

	if !authorized {
		return status.Error(codes.PermissionDenied, "no authorized")
	}

	subscriber := s.manager.SubscribeToBundleChanges()

	// send initial update....
	for td, bundle := range subscriber.Value() {
		resp := &delegationv1.FetchX509BundlesResponse{
			TrustDomainName: td.IDString(),
			Bundle:          marshalBundle(bundle.RootCAs()),
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	for {
		select {
		case <-subscriber.Changes():
			// TODO(Mauricio): cache logic to avoid sending updates for all bundles each time.
			for td, bundle := range subscriber.Next() {
				resp := &delegationv1.FetchX509BundlesResponse{
					TrustDomainName: td.IDString(),
					Bundle:          marshalBundle(bundle.RootCAs()),
				}

				if err := stream.Send(resp); err != nil {
					return err
				}
			}

		case <-ctx.Done():
			return nil
		}
	}
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}
