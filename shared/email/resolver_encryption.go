package email

import (
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// encryptionServiceImpl wraps the encryption service
type encryptionServiceImpl struct {
	service *encryption.Service
}

func newEncryptionServiceImpl(masterKey string) (encryptionService, error) {
	service, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, err
	}
	return &encryptionServiceImpl{service: service}, nil
}

func (e *encryptionServiceImpl) Decrypt(ciphertext string) (string, error) {
	return e.service.Decrypt(ciphertext)
}
