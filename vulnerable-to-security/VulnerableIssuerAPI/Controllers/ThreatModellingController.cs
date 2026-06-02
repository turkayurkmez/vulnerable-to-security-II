using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VulnerableIssuerAPI.ThreatModeling;

namespace VulnerableIssuerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ThreatModellingController : ControllerBase
    {
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<Threat>), StatusCodes.Status200OK)]
        public IActionResult GetAll() => Ok(ThreatRegistry.All);

        [HttpGet("category/{category}")]
        public IActionResult GetByCategory(StrideCategory category) =>
            Ok(ThreatRegistry.ByCategory(category));

        [HttpGet("open")]
        public IActionResult GetOpenThreats() =>
            Ok(ThreatRegistry.All.Where(t => t.MitigationStatus == MitigationStatus.Open));

        [HttpGet("summary")]
        public IActionResult GetSummary()
        {
            var summary = ThreatRegistry.All
                .GroupBy(t => t.Category.ToString())
                .Select(g => new
                {
                    Category = g.Key,
                    Total = g.Count(),
                    Open = g.Count(t => t.MitigationStatus == MitigationStatus.Open),
                    Mitigated = g.Count(t => t.MitigationStatus == MitigationStatus.Mitigated),
                    Accepted = g.Count(t => t.MitigationStatus == MitigationStatus.AcceptedRisk)
                });
            return Ok(summary);

        }
    }
}
