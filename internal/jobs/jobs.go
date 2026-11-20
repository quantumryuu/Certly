// Package jobs runs background work: scheduled revocations and CRL refresh.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/quantumryuu/Certly/internal/ca"
)

// Intervals.
const (
	RevocationInterval = time.Minute
	CRLInterval        = 15 * time.Minute
)

// Run applies scheduled revocations every minute and refreshes CRLs every
// 15 minutes, until ctx is cancelled. It runs both once at start.
func Run(ctx context.Context, svc *ca.Service, log *slog.Logger) {
	tick(ctx, svc, log, true)
	rev := time.NewTicker(RevocationInterval)
	crl := time.NewTicker(CRLInterval)
	defer rev.Stop()
	defer crl.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rev.C:
			tick(ctx, svc, log, false)
		case <-crl.C:
			if err := svc.RefreshCRLs(ctx); err != nil {
				log.Error("CRL refresh failed", "err", err)
			}
		}
	}
}

func tick(ctx context.Context, svc *ca.Service, log *slog.Logger, refresh bool) {
	n, err := svc.ApplyScheduled(ctx)
	if err != nil {
		log.Error("applying scheduled revocations failed", "err", err)
	}
	if n > 0 {
		log.Info("applied scheduled revocations", "count", n)
	}
	if refresh {
		if err := svc.RefreshCRLs(ctx); err != nil {
			log.Error("CRL refresh failed", "err", err)
		}
	}
}
