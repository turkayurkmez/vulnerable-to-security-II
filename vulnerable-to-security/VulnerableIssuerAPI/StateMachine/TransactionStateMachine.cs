namespace VulnerableIssuerAPI.StateMachhine
{
    /// <summary>
    /// Specifies the possible states of a financial transaction during its lifecycle.
    /// </summary>
    /// <remarks>Use this enumeration to determine the current processing status of a transaction, such as
    /// whether it is pending, authorized, settled, or has been declined or reversed. The status can be used to control
    /// business logic or display transaction progress to users.</remarks>
    public enum TransactionStatus
    {
        Pending,
        Authorized,
        Cleared,
        Settled,
        Declined,
        Cancelled,
        Reversed
    }
    //Türkçe dokümantasyon:

    /// <summary>
    /// Bir finansal işlemin yaşam döngüsü boyunca geçebileceği olası durumları belirtir. 
    /// </summary>
    public static class TransactionStateMachine
    {
        private static readonly Dictionary<TransactionStatus, List<TransactionStatus>> AllowedTransitions = new()
        {
            [TransactionStatus.Pending]= [TransactionStatus.Authorized, TransactionStatus.Declined,TransactionStatus.Cancelled],
            [TransactionStatus.Authorized] = [TransactionStatus.Cleared, TransactionStatus.Reversed, TransactionStatus.Cancelled],
            [TransactionStatus.Cleared] = [TransactionStatus.Settled],
            [TransactionStatus.Settled] = [],
            [TransactionStatus.Declined] = [],
            [TransactionStatus.Cancelled] = [],
            [TransactionStatus.Reversed] = []
        };

        public static void Transition(TransactionStatus currentStatus, TransactionStatus target)
        {
            if (!AllowedTransitions[currentStatus].Contains(target))
                throw new InvalidOperationException($"Geçersiz state geçişi: {currentStatus} -> {target}");
          
        }
    }
}
