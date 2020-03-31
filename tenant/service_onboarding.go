package tenant

import (
	"context"
	"fmt"
	"time"

	"github.com/influxdata/influxdb"
	"github.com/influxdata/influxdb/kv"
)

type OnboardService struct {
	store   *Store
	authSvc influxdb.AuthorizationService
}

func NewOnboardService(st *Store, as influxdb.AuthorizationService) influxdb.OnboardingService {
	return &OnboardService{
		store:   st,
		authSvc: as,
	}
}

// IsOnboarding determine if onboarding request is allowed.
func (s *OnboardService) IsOnboarding(ctx context.Context) (bool, error) {
	allowed := false
	err := s.store.View(ctx, func(tx kv.Tx) error {
		// we are allowed to onboard a user if we have no users or orgs
		users, _ := s.store.ListUsers(ctx, tx, influxdb.FindOptions{Limit: 1})
		orgs, _ := s.store.ListOrgs(ctx, tx, influxdb.FindOptions{Limit: 1})
		if len(users) == 0 && len(orgs) == 0 {
			allowed = true
		}
		return nil
	})
	return allowed, err
}

// OnboardInitialUser allows us to onboard a new user if is onboarding is allowd
func (s *OnboardService) OnboardInitialUser(ctx context.Context, req *influxdb.OnboardingRequest) (*influxdb.OnboardingResults, error) {
	allowed, err := s.IsOnboarding(ctx)
	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, ErrOnboardingNotAllowed
	}
	res, err := s.OnboardUser(ctx, req)
	if err != nil {
		return nil, err
	}
	a := &influxdb.Authorization{
		Description: fmt.Sprintf("%s's Token", req.User),
		Permissions: influxdb.OperPermissions(),
		Token:       req.Token,
		UserID:      res.User.ID,
		OrgID:       res.Org.ID,
	}

	if err = s.authSvc.CreateAuthorization(ctx, a); err != nil {
		return nil, err
	}
	res.Auth = a
	return res, nil
}

// OnboardUser allows us to onboard new users.
func (s *OnboardService) OnboardUser(ctx context.Context, req *influxdb.OnboardingRequest) (*influxdb.OnboardingResults, error) {
	if req == nil || req.User == "" || req.Password == "" || req.Org == "" || req.Bucket == "" {
		return nil, ErrOnboardInvalid
	}

	result := &influxdb.OnboardingResults{}

	err := s.store.Update(ctx, func(tx kv.Tx) error {
		// create a user
		user := &influxdb.User{
			Name:   req.User,
			Status: influxdb.Active,
		}

		if err := s.store.CreateUser(ctx, tx, user); err != nil {
			return err
		}

		// create users password
		if req.Password != "" {
			passHash, err := encryptPassword(req.Password)
			if err != nil {
				return err
			}

			s.store.SetPassword(ctx, tx, user.ID, passHash)
		}

		// create users org
		org := &influxdb.Organization{
			Name: req.Org,
		}

		if err := s.store.CreateOrg(ctx, tx, org); err != nil {
			return err
		}

		// create urm
		err := s.store.CreateURM(ctx, tx, &influxdb.UserResourceMapping{
			UserID:       user.ID,
			UserType:     influxdb.Owner,
			MappingType:  influxdb.UserMappingType,
			ResourceType: influxdb.OrgsResourceType,
			ResourceID:   org.ID,
		})
		if err != nil {
			return err
		}

		ub := &influxdb.Bucket{
			Name:            req.Bucket,
			RetentionPeriod: time.Duration(req.RetentionPeriod) * time.Hour,
		}

		// create orgs buckets
		tb := &influxdb.Bucket{
			OrgID:           org.ID,
			Type:            influxdb.BucketTypeSystem,
			Name:            influxdb.TasksSystemBucketName,
			RetentionPeriod: influxdb.TasksSystemBucketRetention,
			Description:     "System bucket for task logs",
		}

		if err := s.store.CreateBucket(ctx, tx, tb); err != nil {
			return err
		}

		mb := &influxdb.Bucket{
			OrgID:           org.ID,
			Type:            influxdb.BucketTypeSystem,
			Name:            influxdb.MonitoringSystemBucketName,
			RetentionPeriod: influxdb.MonitoringSystemBucketRetention,
			Description:     "System bucket for monitoring logs",
		}

		if err := s.store.CreateBucket(ctx, tx, mb); err != nil {
			return err
		}

		result.User = user
		result.Org = org
		result.Bucket = ub
		return nil
	})
	return result, err
}
