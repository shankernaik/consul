package topology

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hashicorp/consul/api"

	libassert "github.com/hashicorp/consul/test/integration/consul-container/libs/assert"
	libcluster "github.com/hashicorp/consul/test/integration/consul-container/libs/cluster"
	libservice "github.com/hashicorp/consul/test/integration/consul-container/libs/service"
	"github.com/hashicorp/consul/test/integration/consul-container/libs/utils"
)

const (
	AcceptingPeerName = "accepting-to-dialer"
	DialingPeerName   = "dialing-to-acceptor"
)

type BuiltCluster struct {
	Cluster   *libcluster.Cluster
	Context   *libcluster.BuildContext
	Service   libservice.Service
	Container *libservice.ConnectContainer
}

// BasicPeeringTwoClustersSetup sets up a scenario for testing peering, which consists of
//
//   - an accepting cluster with 3 servers and 1 client agent. The client should be used to
//     host a service for export: staticServerSvc.
//   - an dialing cluster with 1 server and 1 client. The client should be used to host a
//     service connecting to staticServerSvc.
//   - Create the peering, export the service from accepting cluster, and verify service
//     connectivity.
//
// It returns objects of the accepting cluster, dialing cluster, staticServerSvc, and staticClientSvcSidecar
func BasicPeeringTwoClustersSetup(
	t *testing.T,
	consulVersion string,
) (*BuiltCluster, *BuiltCluster) {
	acceptingCluster, acceptingCtx, acceptingClient := NewPeeringCluster(t, "dc1", 3, consulVersion)
	dialingCluster, dialingCtx, dialingClient := NewPeeringCluster(t, "dc2", 1, consulVersion)
	require.NoError(t, dialingCluster.PeerWithCluster(acceptingClient, AcceptingPeerName, DialingPeerName))

	libassert.PeeringStatus(t, acceptingClient, AcceptingPeerName, api.PeeringStateActive)
	// libassert.PeeringExports(t, acceptingClient, acceptingPeerName, 1)

	// Register an static-server service in acceptingCluster and export to dialing cluster
	var serverSidecarService libservice.Service
	{
		clientNode := acceptingCluster.Clients()[0]

		// Create a service and proxy instance
		var err error
		serverSidecarService, _, err := libservice.CreateAndRegisterStaticServerAndSidecar(clientNode)
		require.NoError(t, err)

		libassert.CatalogServiceExists(t, acceptingClient, "static-server")
		libassert.CatalogServiceExists(t, acceptingClient, "static-server-sidecar-proxy")

		require.NoError(t, serverSidecarService.Export("default", AcceptingPeerName, acceptingClient))

	}

	// Register an static-client service in dialing cluster and set upstream to static-server service
	var clientSidecarService *libservice.ConnectContainer
	{
		clientNode := dialingCluster.Clients()[0]

		// Create a service and proxy instance
		var err error
		clientSidecarService, err = libservice.CreateAndRegisterStaticClientSidecar(clientNode, DialingPeerName, true)
		require.NoError(t, err)

		libassert.CatalogServiceExists(t, dialingClient, "static-client-sidecar-proxy")
	}

	_, port := clientSidecarService.GetAddr()
	libassert.HTTPServiceEchoes(t, "localhost", port, "")

	return &BuiltCluster{
			Cluster:   acceptingCluster,
			Context:   acceptingCtx,
			Service:   serverSidecarService,
			Container: nil,
		},
		&BuiltCluster{
			Cluster:   dialingCluster,
			Context:   dialingCtx,
			Service:   nil,
			Container: clientSidecarService,
		}
}

// NewDialingCluster creates a cluster for peering with a single dev agent
// TODO: note: formerly called CreatingPeeringClusterAndSetup
//
// Deprecated: use NewPeeringCluster mostly
func NewDialingCluster(
	t *testing.T,
	version string,
	dialingPeerName string,
) (*libcluster.Cluster, *api.Client, libservice.Service) {
	t.Helper()
	t.Logf("creating the dialing cluster")

	opts := libcluster.BuildOptions{
		Datacenter:             "dc2",
		InjectAutoEncryption:   true,
		InjectGossipEncryption: true,
		AllowHTTPAnyway:        true,
		ConsulVersion:          version,
	}
	ctx := libcluster.NewBuildContext(t, opts)

	conf := libcluster.NewConfigBuilder(ctx).
		Peering(true).
		ToAgentConfig(t)
	t.Logf("dc2 server config: \n%s", conf.JSON)

	cluster, err := libcluster.NewN(t, *conf, 1)
	require.NoError(t, err)

	node := cluster.Agents[0]
	client := node.GetClient()
	libcluster.WaitForLeader(t, cluster, client)
	libcluster.WaitForMembers(t, client, 1)

	// Default Proxy Settings
	ok, err := utils.ApplyDefaultProxySettings(client)
	require.NoError(t, err)
	require.True(t, ok)

	// Create the mesh gateway for dataplane traffic
	_, err = libservice.NewGatewayService(context.Background(), "mesh", "mesh", node)
	require.NoError(t, err)

	// Create a service and proxy instance
	clientProxyService, err := libservice.CreateAndRegisterStaticClientSidecar(node, dialingPeerName, true)
	require.NoError(t, err)

	libassert.CatalogServiceExists(t, client, "static-client-sidecar-proxy")

	return cluster, client, clientProxyService
}

// NewPeeringCluster creates a cluster with peering enabled. It also creates
// and registers a mesh-gateway at the client agent. The API client returned is
// pointed at the client agent.
func NewPeeringCluster(
	t *testing.T,
	datacenter string,
	numServers int,
	version string,
) (*libcluster.Cluster, *libcluster.BuildContext, *api.Client) {
	require.NotEmpty(t, datacenter)
	require.True(t, numServers > 0)

	opts := libcluster.BuildOptions{
		Datacenter:             datacenter,
		InjectAutoEncryption:   true,
		InjectGossipEncryption: true,
		AllowHTTPAnyway:        true,
		ConsulVersion:          version,
	}
	ctx := libcluster.NewBuildContext(t, opts)

	serverConf := libcluster.NewConfigBuilder(ctx).
		Bootstrap(numServers).
		Peering(true).
		ToAgentConfig(t)
	t.Logf("%s server config: \n%s", datacenter, serverConf.JSON)

	cluster, err := libcluster.NewN(t, *serverConf, numServers)
	require.NoError(t, err)

	var retryJoin []string
	for i := 0; i < numServers; i++ {
		retryJoin = append(retryJoin, fmt.Sprintf("agent-%d", i))
	}

	// Add a stable client to register the service
	clientConf := libcluster.NewConfigBuilder(ctx).
		Client().
		Peering(true).
		RetryJoin(retryJoin...).
		ToAgentConfig(t)
	t.Logf("%s server config: \n%s", datacenter, clientConf.JSON)

	require.NoError(t, cluster.AddN(*clientConf, 1, true))

	// Use the client agent as the HTTP endpoint since we will not rotate it in many tests.
	clientNode := cluster.Agents[numServers]
	client := clientNode.GetClient()
	libcluster.WaitForLeader(t, cluster, client)
	libcluster.WaitForMembers(t, client, numServers+1)

	// Default Proxy Settings
	ok, err := utils.ApplyDefaultProxySettings(client)
	require.NoError(t, err)
	require.True(t, ok)

	// Create the mesh gateway for dataplane traffic
	_, err = libservice.NewGatewayService(context.Background(), "mesh", "mesh", clientNode)
	require.NoError(t, err)

	return cluster, ctx, client
}
