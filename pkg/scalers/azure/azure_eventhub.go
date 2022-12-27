package azure

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-amqp-common-go/v3/aad"
	eventhub "github.com/Azure/azure-event-hubs-go/v3"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/go-logr/logr"

	kedav1alpha1 "github.com/kedacore/keda/v2/apis/keda/v1alpha1"
)

// EventHubInfo to keep event hub connection and resources
type EventHubInfo struct {
	EventHubConnection    string
	EventHubConsumerGroup string
	StorageConnection     string
	// +optional
	StorageAccountName       string
	BlobStorageEndpoint      string
	BlobContainer            string
	Namespace                string
	EventHubName             string
	CheckpointStrategy       string
	ServiceBusEndpointSuffix string
	ActiveDirectoryEndpoint  string
	EventHubResourceURL      string
	// +optional
	CheckpointIdentityID string
	// +optional
	CheckpointTenantID string
	PodIdentity        kedav1alpha1.AuthPodIdentity
	// +optional
	Certificate string
}

const (
	DefaultEventhubResourceURL = "https://eventhubs.azure.net/"
)

// GetEventHubClient returns eventhub client
func GetEventHubClient(logger logr.Logger, ctx context.Context, info EventHubInfo) (*eventhub.Hub, error) {
	switch info.PodIdentity.Provider {
	case "", kedav1alpha1.PodIdentityProviderNone:
		// The user wants to use a connectionstring, not a pod identity
		hub, err := eventhub.NewHubFromConnectionString(info.EventHubConnection)
		if err != nil {
			return nil, fmt.Errorf("failed to create hub client: %s", err)
		}
		return hub, nil
	case kedav1alpha1.PodIdentityProviderAzureServicePrincipal:
		env := azure.Environment{ActiveDirectoryEndpoint: info.ActiveDirectoryEndpoint, ServiceBusEndpointSuffix: info.ServiceBusEndpointSuffix}
		hubEnvOptions := eventhub.HubWithEnvironment(env)

		envJWTProviderOption := aad.JWTProviderWithAzureEnvironment(&env)
		resourceURLJWTProviderOption := aad.JWTProviderWithResourceURI(info.EventHubResourceURL)
		oauthConfig, _ := adal.NewOAuthConfig(info.ActiveDirectoryEndpoint, info.PodIdentity.TenantID)
		certificate, privateKey, err := LoadCertAndKeyFromSecret([]byte(info.Certificate))

		if err != nil {
			return nil, fmt.Errorf("unable to load certificate %v", err)
		}
		servicePrincipalToken, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, info.PodIdentity.ClientID, certificate, privateKey, info.EventHubResourceURL)

		if err != nil {
			return nil, fmt.Errorf("failed to get oauth token from certificate auth: %v", err)
		}

		aadFuncOption := aad.JWTProviderWithAADToken(servicePrincipalToken)
		clientIDJWTProviderOption := func(config *aad.TokenProviderConfiguration) error {
			config.TenantID = info.PodIdentity.TenantID
			config.ClientID = info.PodIdentity.ClientID
			config.Env = &env
			return nil
		}

		provider, aadErr := aad.NewJWTProvider(envJWTProviderOption, resourceURLJWTProviderOption, clientIDJWTProviderOption, aadFuncOption)

		if aadErr != nil {
			return nil, fmt.Errorf("failed to get refresh oauth token from certificate auth: %v", err)
		}

		if aadErr == nil {
			token, err := provider.GetToken(info.PodIdentity.Audience) // dummy change this
			if err != nil {
				logger.Error(err, "unable to get eventhub client")
			}
			logger.Info("Token retrieved from AAD: %s", token)

			return eventhub.NewHub(info.Namespace, info.EventHubName, provider, hubEnvOptions)
		}

		return nil, aadErr

	case kedav1alpha1.PodIdentityProviderAzure:
		env := azure.Environment{ActiveDirectoryEndpoint: info.ActiveDirectoryEndpoint, ServiceBusEndpointSuffix: info.ServiceBusEndpointSuffix}
		hubEnvOptions := eventhub.HubWithEnvironment(env)
		// Since there is no connectionstring, then user wants to use AAD Pod identity
		// Internally, the JWTProvider will use Managed Service Identity to authenticate if no Service Principal info supplied
		envJWTProviderOption := aad.JWTProviderWithAzureEnvironment(&env)
		resourceURLJWTProviderOption := aad.JWTProviderWithResourceURI(info.EventHubResourceURL)
		clientIDJWTProviderOption := func(config *aad.TokenProviderConfiguration) error {
			config.ClientID = info.PodIdentity.IdentityID
			return nil
		}

		provider, aadErr := aad.NewJWTProvider(envJWTProviderOption, resourceURLJWTProviderOption, clientIDJWTProviderOption)

		if aadErr == nil {
			return eventhub.NewHub(info.Namespace, info.EventHubName, provider, hubEnvOptions)
		}

		return nil, aadErr
	case kedav1alpha1.PodIdentityProviderAzureWorkload:
		// User wants to use AAD Workload Identity
		env := azure.Environment{ActiveDirectoryEndpoint: info.ActiveDirectoryEndpoint, ServiceBusEndpointSuffix: info.ServiceBusEndpointSuffix}
		hubEnvOptions := eventhub.HubWithEnvironment(env)
		provider := NewAzureADWorkloadIdentityTokenProvider(ctx, info.PodIdentity.IdentityID, info.PodIdentity.TenantID, info.EventHubResourceURL)

		return eventhub.NewHub(info.Namespace, info.EventHubName, provider, hubEnvOptions)
	}

	return nil, fmt.Errorf("event hub does not support pod identity %v", info.PodIdentity)
}

// LoadCertAndKeyFromSecret takes the encoded PEM and tries to extract the Certificate and Private Key
func LoadCertAndKeyFromSecret(pemBytes []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var certificate *x509.Certificate
	var privateKey *rsa.PrivateKey
	for len(pemBytes) > 0 {
		data, block := pem.Decode(pemBytes)
		if block == nil {
			return nil, nil, fmt.Errorf("no certificate or private key block found")
		}
		if data.Type == "CERTIFICATE" {
			var err error
			certificate, err = x509.ParseCertificate(data.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("error while decoding certificate %v", err)
			}
			if privateKey != nil {
				break
			}
		}
		if data.Type == "PRIVATE KEY" {
			var err error
			anypk, err := x509.ParsePKCS8PrivateKey(data.Bytes)
			if err == nil {
				switch key := anypk.(type) {
				case *rsa.PrivateKey:
					privateKey = key
				default:
					return nil, nil, fmt.Errorf("found unknown private key type in pkcs#8 wrapping")
				}
			}
			if err != nil {
				return nil, nil, fmt.Errorf("malformed private key detected %v", err)
			}

		}
		pemBytes = block
	}

	return certificate, privateKey, nil
}

// ParseAzureEventHubConnectionString parses Event Hub connection string into (namespace, name)
// Connection string should be in following format:
// Endpoint=sb://eventhub-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=secretKey123;EntityPath=eventhub-name
func ParseAzureEventHubConnectionString(connectionString string) (string, string, error) {
	parts := strings.Split(connectionString, ";")

	var eventHubNamespace, eventHubName string
	for _, v := range parts {
		if strings.HasPrefix(v, "Endpoint") {
			endpointParts := strings.SplitN(v, "=", 2)
			if len(endpointParts) == 2 {
				endpointParts[1] = strings.TrimPrefix(endpointParts[1], "sb://")
				endpointParts[1] = strings.TrimSuffix(endpointParts[1], "/")
				eventHubNamespace = endpointParts[1]
			}
		} else if strings.HasPrefix(v, "EntityPath") {
			entityPathParts := strings.SplitN(v, "=", 2)
			if len(entityPathParts) == 2 {
				eventHubName = entityPathParts[1]
			}
		}
	}

	if eventHubNamespace == "" || eventHubName == "" {
		return "", "", errors.New("can't parse event hub connection string. Missing eventHubNamespace or eventHubName")
	}

	return eventHubNamespace, eventHubName, nil
}

func getHubAndNamespace(info EventHubInfo) (string, string, error) {
	var eventHubNamespace string
	var eventHubName string
	var err error
	if info.EventHubConnection != "" {
		eventHubNamespace, eventHubName, err = ParseAzureEventHubConnectionString(info.EventHubConnection)
		if err != nil {
			return "", "", err
		}
	} else {
		eventHubNamespace = fmt.Sprintf("%s.%s", info.Namespace, info.ServiceBusEndpointSuffix)
		eventHubName = info.EventHubName
	}

	return eventHubNamespace, eventHubName, nil
}
