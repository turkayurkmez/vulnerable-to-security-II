using System.Collections.Concurrent;

namespace VulnerableIssuerAPI.Services
{
    public class IdempotencyService
    {
        private readonly ConcurrentDictionary<string, IdempotencyRecord> _store = new();
        private readonly TimeSpan ttl = TimeSpan.FromHours(24);

        public void StoreRecord(string key, string transactionId, object? response)
        {
            var record = new IdempotencyRecord
            {
                Key = key,
                TransactionId = transactionId,
                CachedResponse = response,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(ttl)
            };
            _store.GetOrAdd(key, record);
        }

        public IdempotencyRecord? GetExistingRecord(string key)
        {
            if (_store.TryGetValue(key, out var record))
            {
                if (record.ExpiresAt > DateTime.UtcNow)
                {
                    return record;
                }
                else
                {
                    _store.TryRemove(key, out _);
                }
            }
            return null;
        }
    }

    public class IdempotencyRecord
    {
        public string Key { get; set; } = string.Empty;
        public string TransactionId { get; set; } = string.Empty;
        public object? CachedResponse { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

}
