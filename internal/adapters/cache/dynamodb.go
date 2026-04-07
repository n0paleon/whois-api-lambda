package cache

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
	"whois-api-lambda/internal/apperrors"
	"whois-api-lambda/internal/domain"
	"whois-api-lambda/internal/ports"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoDBCache struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoDBCache(tableName string) (ports.CacheService, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	client := dynamodb.NewFromConfig(cfg)

	return &DynamoDBCache{
		client:    client,
		tableName: tableName,
	}, nil
}

func (c *DynamoDBCache) GetRaw(ctx context.Context, query string) (string, error) {
	key := "RAW:" + query
	item, err := c.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.tableName),
		Key: map[string]types.AttributeValue{
			"Domain": &types.AttributeValueMemberS{Value: key},
		},
	})
	if err != nil {
		return "", err
	}
	if item.Item == nil {
		return "", apperrors.ErrNotFound
	}
	if c.isExpired(item.Item) {
		return "", apperrors.ErrNotFound
	}
	if rawAttr, ok := item.Item["RawData"]; ok {
		if raw, ok := rawAttr.(*types.AttributeValueMemberS); ok {
			return raw.Value, nil
		}
	}

	return "", apperrors.ErrNotFound
}

func (c *DynamoDBCache) SetRaw(ctx context.Context, query string, data string, ttl time.Duration) error {
	key := "RAW:" + query
	expiresAt := time.Now().Add(ttl).Unix()
	_, err := c.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.tableName),
		Item: map[string]types.AttributeValue{
			"Domain":    &types.AttributeValueMemberS{Value: key},
			"RawData":   &types.AttributeValueMemberS{Value: data},
			"ExpiresAt": &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt, 10)},
		},
	})
	return err
}

func (c *DynamoDBCache) GetParsed(ctx context.Context, query string) (*domain.WhoisInfo, error) {
	key := "PARSED:" + query
	item, err := c.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(c.tableName),
		Key:       map[string]types.AttributeValue{"Domain": &types.AttributeValueMemberS{Value: key}},
	})
	if err != nil {
		return nil, err
	}
	if item.Item == nil {
		return nil, apperrors.ErrNotFound
	}
	if c.isExpired(item.Item) {
		return nil, apperrors.ErrNotFound
	}
	if parsedAttr, ok := item.Item["ParsedData"]; ok {
		if parsedStr, ok := parsedAttr.(*types.AttributeValueMemberS); ok {
			var info domain.WhoisInfo
			if err := json.Unmarshal([]byte(parsedStr.Value), &info); err != nil {
				return nil, err
			}
			return &info, nil
		}
	}

	return nil, apperrors.ErrNotFound
}

func (c *DynamoDBCache) SetParsed(ctx context.Context, query string, data *domain.WhoisInfo, ttl time.Duration) error {
	key := "PARSED:" + query
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	expiresAt := time.Now().Add(ttl).Unix()
	_, err = c.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(c.tableName),
		Item: map[string]types.AttributeValue{
			"Domain":     &types.AttributeValueMemberS{Value: key},
			"ParsedData": &types.AttributeValueMemberS{Value: string(jsonData)},
			"ExpiresAt":  &types.AttributeValueMemberN{Value: strconv.FormatInt(expiresAt, 10)},
		},
	})
	return err
}

func (c *DynamoDBCache) isExpired(item map[string]types.AttributeValue) bool {
	if expiresAtAttr, ok := item["ExpiresAt"]; ok {
		if expiresAtStr, ok := expiresAtAttr.(*types.AttributeValueMemberN); ok {
			expiresAt, _ := strconv.ParseInt(expiresAtStr.Value, 10, 64)
			return time.Now().Unix() >= expiresAt
		}
	}
	return true
}
