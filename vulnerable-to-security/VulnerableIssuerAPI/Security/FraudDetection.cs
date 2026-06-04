using Microsoft.EntityFrameworkCore;
using VulnerableIssuerAPI.Data;
using VulnerableIssuerAPI.Models.DTOs;
using VulnerableIssuerAPI.Models.Entities;

namespace VulnerableIssuerAPI.Security
{
    public class FraudDetection
    {
        public static async Task<int> EvaluateFraudRiskAsync(AuthorizationRequest request, Card card, VulnerableDbContext dbContext )
        {
            var score = 0;

            //Rule 1: Velocity check: son 1 saatte yapılan işlemlerin sayısı
            var recentTransactions = await dbContext.Transactions
                .CountAsync(t => t.CardId == card.Id && 
                                 t.CreatedAt >= DateTime.UtcNow.AddHours(-1));


            if (recentTransactions >= 10)
            {
                score += 40; 
               
            }
            else if(recentTransactions >= 5)
            {
                score += 20;
            }

            //Aslında negatif tutar ve max işlem de bu metotta olabilirdi.
            //Rule 2: Blacklist check: riskli merchant'larla yapılan işlemler
            var isBlacklistedMerchant = await IsBlackListMerchantAsync(request.MerchantId);
            if (isBlacklistedMerchant)
            {
                score += 100;
            }

            //Rule 3: Amount check: yüksek tutarlı işlemler
            if (request.Amount > 2000)
            {
                score += 10;
            }
            if (request.Amount>10000)
            {
                score += 25;
            }

            return score;


        }

        private static async Task<bool> IsBlackListMerchantAsync(int merchantId)
        {
           var blackList = new HashSet<int> { 1, 999 }; 
           // Örnek blacklist
           return await Task.FromResult(blackList.Contains(merchantId));
        }
    }
}
