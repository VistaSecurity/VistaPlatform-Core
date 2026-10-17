package main

import (
	"context"
	"database/sql"
	"log"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// initDcimImageStorage builds the shared/storage S3 service for DCIM image
// attachments (artifact type dcim_images), the way cbom-service does for CBOM
// artifacts. It returns nil when it cannot (no ENCRYPTION_MASTER_KEY, or the
// config will not load): the image store then keeps images on the service's
// local disk (DCIM_IMAGE_DIR), so the feature works on a brand-new install. A
// later admin switch of dcim_images on in Settings takes effect on the next
// start (Reload is not wired to a signal here).
func initDcimImageStorage(db, bypassDB *sql.DB) sharedstorage.ArtifactStorageService {
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		log.Printf("[dcim-images] ENCRYPTION_MASTER_KEY not set — images are kept on local disk")
		return nil
	}
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		log.Printf("[dcim-images] encryption service: %v — images are kept on local disk", err)
		return nil
	}
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	svc := sharedstorage.NewS3StorageService(
		sharedstorage.NewDatabaseConfigProvider(db),
		sharedstorage.NewDatabaseIntegrationProvider(bypassDB, enc),
		logger)
	if err := svc.Reload(context.Background()); err != nil {
		log.Printf("[dcim-images] storage config did not load: %v — images are kept on local disk", err)
		return nil
	}
	log.Printf("[dcim-images] storage service ready (dcim_images enabled = %v)", svc.IsEnabled(sharedstorage.ArtifactTypeDcimImages))
	return svc
}
