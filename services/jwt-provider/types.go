package jwt_provider

type CreateJWTMessage struct {
	Claims map[string]interface{} `json:"claims"`
}
type CreateJWTResponse struct {
	Token string `json:"token"`
}
type RegisterScannerAddressMessage struct {
	Claims map[string]string `json:"claims"`
}
type RegisterScannerAddressResponse struct {
	Token string `json:"token"`
}
