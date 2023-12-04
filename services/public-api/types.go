package public_api

type RegisterScannerAddressMessage struct {
	Claims map[string]interface{} `json:"claims"`
}
type RegisterScannerAddressResponse struct {
	Token string `json:"token"`
}
