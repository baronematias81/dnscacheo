package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client     *redis.Client
	defaultTTL time.Duration
}

func NewRedisCache(cfg interface{}) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	return &RedisCache{
		client:     client,
		defaultTTL: 300 * time.Second,
	}
}

func (c *RedisCache) key(name string, qtype uint16) string {
	return fmt.Sprintf("dns:%s:%d", name, qtype)
}

func (c *RedisCache) Get(name string, qtype uint16) []dns.RR {
	ctx := context.Background()
	val, err := c.client.Get(ctx, c.key(name, qtype)).Bytes()
	if err != nil {
		return nil
	}

	var records []string
	if err := json.Unmarshal(val, &records); err != nil {
		return nil
	}

	var rrs []dns.RR
	for _, r := range records {
		rr, err := dns.NewRR(r)
		if err == nil {
			rrs = append(rrs, rr)
		}
	}
	return rrs
}

func (c *RedisCache) Set(name string, qtype uint16, rrs []dns.RR) {
	ctx := context.Background()

	var records []string
	ttl := c.defaultTTL

	for _, rr := range rrs {
		records = append(records, rr.String())
		rrTTL := time.Duration(rr.Header().Ttl) * time.Second
		if rrTTL > 0 && rrTTL < ttl {
			ttl = rrTTL
		}
	}

	data, err := json.Marshal(records)
	if err != nil {
		return
	}

	c.client.Set(ctx, c.key(name, qtype), data, ttl)
}

func (c *RedisCache) Delete(name string, qtype uint16) {
	ctx := context.Background()
	c.client.Del(ctx, c.key(name, qtype))
}

func (c *RedisCache) Flush() {
	ctx := context.Background()
	c.client.FlushDB(ctx)
}
