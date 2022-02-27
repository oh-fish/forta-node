// Code generated by MockGen. DO NOT EDIT.
// Source: clients/interfaces.go

// Package mock_clients is a generated GoMock package.
package mock_clients

import (
	context "context"
	reflect "reflect"

	types "github.com/docker/docker/api/types"
	domain "github.com/forta-protocol/forta-core-go/domain"
	protocol "github.com/forta-protocol/forta-core-go/protocol"
	clients "github.com/forta-protocol/forta-node/clients"
	config "github.com/forta-protocol/forta-node/config"
	gomock "github.com/golang/mock/gomock"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
)

// MockDockerClient is a mock of DockerClient interface.
type MockDockerClient struct {
	ctrl     *gomock.Controller
	recorder *MockDockerClientMockRecorder
}

// MockDockerClientMockRecorder is the mock recorder for MockDockerClient.
type MockDockerClientMockRecorder struct {
	mock *MockDockerClient
}

// NewMockDockerClient creates a new mock instance.
func NewMockDockerClient(ctrl *gomock.Controller) *MockDockerClient {
	mock := &MockDockerClient{ctrl: ctrl}
	mock.recorder = &MockDockerClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDockerClient) EXPECT() *MockDockerClientMockRecorder {
	return m.recorder
}

// AttachNetwork mocks base method.
func (m *MockDockerClient) AttachNetwork(ctx context.Context, containerID, networkID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AttachNetwork", ctx, containerID, networkID)
	ret0, _ := ret[0].(error)
	return ret0
}

// AttachNetwork indicates an expected call of AttachNetwork.
func (mr *MockDockerClientMockRecorder) AttachNetwork(ctx, containerID, networkID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AttachNetwork", reflect.TypeOf((*MockDockerClient)(nil).AttachNetwork), ctx, containerID, networkID)
}

// CreateInternalNetwork mocks base method.
func (m *MockDockerClient) CreateInternalNetwork(ctx context.Context, name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateInternalNetwork", ctx, name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateInternalNetwork indicates an expected call of CreateInternalNetwork.
func (mr *MockDockerClientMockRecorder) CreateInternalNetwork(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateInternalNetwork", reflect.TypeOf((*MockDockerClient)(nil).CreateInternalNetwork), ctx, name)
}

// CreatePublicNetwork mocks base method.
func (m *MockDockerClient) CreatePublicNetwork(ctx context.Context, name string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreatePublicNetwork", ctx, name)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreatePublicNetwork indicates an expected call of CreatePublicNetwork.
func (mr *MockDockerClientMockRecorder) CreatePublicNetwork(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreatePublicNetwork", reflect.TypeOf((*MockDockerClient)(nil).CreatePublicNetwork), ctx, name)
}

// EnsureLocalImage mocks base method.
func (m *MockDockerClient) EnsureLocalImage(ctx context.Context, name, ref string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EnsureLocalImage", ctx, name, ref)
	ret0, _ := ret[0].(error)
	return ret0
}

// EnsureLocalImage indicates an expected call of EnsureLocalImage.
func (mr *MockDockerClientMockRecorder) EnsureLocalImage(ctx, name, ref interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EnsureLocalImage", reflect.TypeOf((*MockDockerClient)(nil).EnsureLocalImage), ctx, name, ref)
}

// GetContainerByID mocks base method.
func (m *MockDockerClient) GetContainerByID(ctx context.Context, id string) (*types.Container, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContainerByID", ctx, id)
	ret0, _ := ret[0].(*types.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContainerByID indicates an expected call of GetContainerByID.
func (mr *MockDockerClientMockRecorder) GetContainerByID(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContainerByID", reflect.TypeOf((*MockDockerClient)(nil).GetContainerByID), ctx, id)
}

// GetContainerByName mocks base method.
func (m *MockDockerClient) GetContainerByName(ctx context.Context, name string) (*types.Container, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContainerByName", ctx, name)
	ret0, _ := ret[0].(*types.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContainerByName indicates an expected call of GetContainerByName.
func (mr *MockDockerClientMockRecorder) GetContainerByName(ctx, name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContainerByName", reflect.TypeOf((*MockDockerClient)(nil).GetContainerByName), ctx, name)
}

// GetContainerLogs mocks base method.
func (m *MockDockerClient) GetContainerLogs(ctx context.Context, containerID, tail string, truncate int) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContainerLogs", ctx, containerID, tail, truncate)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContainerLogs indicates an expected call of GetContainerLogs.
func (mr *MockDockerClientMockRecorder) GetContainerLogs(ctx, containerID, tail, truncate interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContainerLogs", reflect.TypeOf((*MockDockerClient)(nil).GetContainerLogs), ctx, containerID, tail, truncate)
}

// GetContainers mocks base method.
func (m *MockDockerClient) GetContainers(ctx context.Context) (clients.DockerContainerList, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetContainers", ctx)
	ret0, _ := ret[0].(clients.DockerContainerList)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetContainers indicates an expected call of GetContainers.
func (mr *MockDockerClientMockRecorder) GetContainers(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetContainers", reflect.TypeOf((*MockDockerClient)(nil).GetContainers), ctx)
}

// GetFortaServiceContainers mocks base method.
func (m *MockDockerClient) GetFortaServiceContainers(ctx context.Context) (clients.DockerContainerList, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFortaServiceContainers", ctx)
	ret0, _ := ret[0].(clients.DockerContainerList)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFortaServiceContainers indicates an expected call of GetFortaServiceContainers.
func (mr *MockDockerClientMockRecorder) GetFortaServiceContainers(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFortaServiceContainers", reflect.TypeOf((*MockDockerClient)(nil).GetFortaServiceContainers), ctx)
}

// HasLocalImage mocks base method.
func (m *MockDockerClient) HasLocalImage(ctx context.Context, ref string) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HasLocalImage", ctx, ref)
	ret0, _ := ret[0].(bool)
	return ret0
}

// HasLocalImage indicates an expected call of HasLocalImage.
func (mr *MockDockerClientMockRecorder) HasLocalImage(ctx, ref interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HasLocalImage", reflect.TypeOf((*MockDockerClient)(nil).HasLocalImage), ctx, ref)
}

// InterruptContainer mocks base method.
func (m *MockDockerClient) InterruptContainer(ctx context.Context, ID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InterruptContainer", ctx, ID)
	ret0, _ := ret[0].(error)
	return ret0
}

// InterruptContainer indicates an expected call of InterruptContainer.
func (mr *MockDockerClientMockRecorder) InterruptContainer(ctx, ID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InterruptContainer", reflect.TypeOf((*MockDockerClient)(nil).InterruptContainer), ctx, ID)
}

// Nuke mocks base method.
func (m *MockDockerClient) Nuke(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Nuke", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Nuke indicates an expected call of Nuke.
func (mr *MockDockerClientMockRecorder) Nuke(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Nuke", reflect.TypeOf((*MockDockerClient)(nil).Nuke), ctx)
}

// Prune mocks base method.
func (m *MockDockerClient) Prune(ctx context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Prune", ctx)
	ret0, _ := ret[0].(error)
	return ret0
}

// Prune indicates an expected call of Prune.
func (mr *MockDockerClientMockRecorder) Prune(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Prune", reflect.TypeOf((*MockDockerClient)(nil).Prune), ctx)
}

// PullImage mocks base method.
func (m *MockDockerClient) PullImage(ctx context.Context, refStr string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PullImage", ctx, refStr)
	ret0, _ := ret[0].(error)
	return ret0
}

// PullImage indicates an expected call of PullImage.
func (mr *MockDockerClientMockRecorder) PullImage(ctx, refStr interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PullImage", reflect.TypeOf((*MockDockerClient)(nil).PullImage), ctx, refStr)
}

// StartContainer mocks base method.
func (m *MockDockerClient) StartContainer(ctx context.Context, config clients.DockerContainerConfig) (*clients.DockerContainer, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartContainer", ctx, config)
	ret0, _ := ret[0].(*clients.DockerContainer)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// StartContainer indicates an expected call of StartContainer.
func (mr *MockDockerClientMockRecorder) StartContainer(ctx, config interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartContainer", reflect.TypeOf((*MockDockerClient)(nil).StartContainer), ctx, config)
}

// StopContainer mocks base method.
func (m *MockDockerClient) StopContainer(ctx context.Context, ID string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StopContainer", ctx, ID)
	ret0, _ := ret[0].(error)
	return ret0
}

// StopContainer indicates an expected call of StopContainer.
func (mr *MockDockerClientMockRecorder) StopContainer(ctx, ID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StopContainer", reflect.TypeOf((*MockDockerClient)(nil).StopContainer), ctx, ID)
}

// WaitContainerExit mocks base method.
func (m *MockDockerClient) WaitContainerExit(ctx context.Context, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitContainerExit", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// WaitContainerExit indicates an expected call of WaitContainerExit.
func (mr *MockDockerClientMockRecorder) WaitContainerExit(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitContainerExit", reflect.TypeOf((*MockDockerClient)(nil).WaitContainerExit), ctx, id)
}

// WaitContainerPrune mocks base method.
func (m *MockDockerClient) WaitContainerPrune(ctx context.Context, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitContainerPrune", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// WaitContainerPrune indicates an expected call of WaitContainerPrune.
func (mr *MockDockerClientMockRecorder) WaitContainerPrune(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitContainerPrune", reflect.TypeOf((*MockDockerClient)(nil).WaitContainerPrune), ctx, id)
}

// WaitContainerStart mocks base method.
func (m *MockDockerClient) WaitContainerStart(ctx context.Context, id string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WaitContainerStart", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// WaitContainerStart indicates an expected call of WaitContainerStart.
func (mr *MockDockerClientMockRecorder) WaitContainerStart(ctx, id interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WaitContainerStart", reflect.TypeOf((*MockDockerClient)(nil).WaitContainerStart), ctx, id)
}

// MockMessageClient is a mock of MessageClient interface.
type MockMessageClient struct {
	ctrl     *gomock.Controller
	recorder *MockMessageClientMockRecorder
}

// MockMessageClientMockRecorder is the mock recorder for MockMessageClient.
type MockMessageClientMockRecorder struct {
	mock *MockMessageClient
}

// NewMockMessageClient creates a new mock instance.
func NewMockMessageClient(ctrl *gomock.Controller) *MockMessageClient {
	mock := &MockMessageClient{ctrl: ctrl}
	mock.recorder = &MockMessageClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMessageClient) EXPECT() *MockMessageClientMockRecorder {
	return m.recorder
}

// Publish mocks base method.
func (m *MockMessageClient) Publish(subject string, payload interface{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Publish", subject, payload)
}

// Publish indicates an expected call of Publish.
func (mr *MockMessageClientMockRecorder) Publish(subject, payload interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Publish", reflect.TypeOf((*MockMessageClient)(nil).Publish), subject, payload)
}

// PublishProto mocks base method.
func (m *MockMessageClient) PublishProto(subject string, payload proto.Message) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PublishProto", subject, payload)
}

// PublishProto indicates an expected call of PublishProto.
func (mr *MockMessageClientMockRecorder) PublishProto(subject, payload interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublishProto", reflect.TypeOf((*MockMessageClient)(nil).PublishProto), subject, payload)
}

// Subscribe mocks base method.
func (m *MockMessageClient) Subscribe(subject string, handler interface{}) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Subscribe", subject, handler)
}

// Subscribe indicates an expected call of Subscribe.
func (mr *MockMessageClientMockRecorder) Subscribe(subject, handler interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Subscribe", reflect.TypeOf((*MockMessageClient)(nil).Subscribe), subject, handler)
}

// MockAgentClient is a mock of AgentClient interface.
type MockAgentClient struct {
	ctrl     *gomock.Controller
	recorder *MockAgentClientMockRecorder
}

// MockAgentClientMockRecorder is the mock recorder for MockAgentClient.
type MockAgentClientMockRecorder struct {
	mock *MockAgentClient
}

// NewMockAgentClient creates a new mock instance.
func NewMockAgentClient(ctrl *gomock.Controller) *MockAgentClient {
	mock := &MockAgentClient{ctrl: ctrl}
	mock.recorder = &MockAgentClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAgentClient) EXPECT() *MockAgentClientMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockAgentClient) Close() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close.
func (mr *MockAgentClientMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockAgentClient)(nil).Close))
}

// Dial mocks base method.
func (m *MockAgentClient) Dial(arg0 config.AgentConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Dial", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Dial indicates an expected call of Dial.
func (mr *MockAgentClientMockRecorder) Dial(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Dial", reflect.TypeOf((*MockAgentClient)(nil).Dial), arg0)
}

// EvaluateBlock mocks base method.
func (m *MockAgentClient) EvaluateBlock(ctx context.Context, in *protocol.EvaluateBlockRequest, opts ...grpc.CallOption) (*protocol.EvaluateBlockResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EvaluateBlock", varargs...)
	ret0, _ := ret[0].(*protocol.EvaluateBlockResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EvaluateBlock indicates an expected call of EvaluateBlock.
func (mr *MockAgentClientMockRecorder) EvaluateBlock(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EvaluateBlock", reflect.TypeOf((*MockAgentClient)(nil).EvaluateBlock), varargs...)
}

// EvaluateTx mocks base method.
func (m *MockAgentClient) EvaluateTx(ctx context.Context, in *protocol.EvaluateTxRequest, opts ...grpc.CallOption) (*protocol.EvaluateTxResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "EvaluateTx", varargs...)
	ret0, _ := ret[0].(*protocol.EvaluateTxResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EvaluateTx indicates an expected call of EvaluateTx.
func (mr *MockAgentClientMockRecorder) EvaluateTx(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EvaluateTx", reflect.TypeOf((*MockAgentClient)(nil).EvaluateTx), varargs...)
}

// Initialize mocks base method.
func (m *MockAgentClient) Initialize(ctx context.Context, in *protocol.InitializeRequest, opts ...grpc.CallOption) (*protocol.InitializeResponse, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, in}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "Initialize", varargs...)
	ret0, _ := ret[0].(*protocol.InitializeResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Initialize indicates an expected call of Initialize.
func (mr *MockAgentClientMockRecorder) Initialize(ctx, in interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, in}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Initialize", reflect.TypeOf((*MockAgentClient)(nil).Initialize), varargs...)
}

// MockAlertAPIClient is a mock of AlertAPIClient interface.
type MockAlertAPIClient struct {
	ctrl     *gomock.Controller
	recorder *MockAlertAPIClientMockRecorder
}

// MockAlertAPIClientMockRecorder is the mock recorder for MockAlertAPIClient.
type MockAlertAPIClientMockRecorder struct {
	mock *MockAlertAPIClient
}

// NewMockAlertAPIClient creates a new mock instance.
func NewMockAlertAPIClient(ctrl *gomock.Controller) *MockAlertAPIClient {
	mock := &MockAlertAPIClient{ctrl: ctrl}
	mock.recorder = &MockAlertAPIClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAlertAPIClient) EXPECT() *MockAlertAPIClientMockRecorder {
	return m.recorder
}

// PostBatch mocks base method.
func (m *MockAlertAPIClient) PostBatch(batch *domain.AlertBatch, token string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PostBatch", batch, token)
	ret0, _ := ret[0].(error)
	return ret0
}

// PostBatch indicates an expected call of PostBatch.
func (mr *MockAlertAPIClientMockRecorder) PostBatch(batch, token interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostBatch", reflect.TypeOf((*MockAlertAPIClient)(nil).PostBatch), batch, token)
}
