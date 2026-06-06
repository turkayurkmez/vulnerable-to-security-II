namespace VulnerableIssuerAPI.Middlewares
{
    public class CorrelationIdMiddleware
    {
        private readonly RequestDelegate _next;
        //aslıda Logger bir ihtiyacı karşılamıyor:
        private readonly ILogger<CorrelationIdMiddleware> _logger;

        public const string CorrelationIdHeader = "X-Correlation-ID";

        public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            var correlationId =context.Request.Headers[CorrelationIdHeader].FirstOrDefault() ?? Guid.NewGuid().ToString();

            context.Response.OnStarting(()=>
            {
                context.Response.Headers[CorrelationIdHeader] = correlationId;
                return Task.CompletedTask;
            });

            using (_logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
            {
                //Dikkat: Gerçek projede Context yerine ILogger'ın BeginScope özelliği kullanılabilir. Bu örnekte basitçe Context.Items kullanarak correlationId'yi erişilebilir hale getiriyoruz.
                context.Items["CorrelationId"] = correlationId; // İstek boyunca erişilebilir hale getir
                _logger.LogInformation("Correlation ID set: {CorrelationId}", correlationId);
                await _next(context); // Sonraki middleware'e geç
            }

        }
    }
}
