namespace Donker.Hmac.Validation
{
    /// <summary>
    /// Contains information about the result of a validation.
    /// </summary>
    public class HmacValidationResult
    {
        /// <summary>
        /// Gets the default OK validation result instance.
        /// </summary>
        public static HmacValidationResult Ok => NestedOk.Instance;

        /// <summary>
        /// Gets the result code describing the result of the validation.
        /// </summary>
        public int ResultCode { get; }

        /// <summary>
        /// Gets the message describing the error of the validation in the case that it failed.
        /// </summary>
        public string ErrorMessage { get; }

        /// <summary>
        /// Initializes a new instance of <see cref="HmacValidationResult"/> using the specified result code and message.
        /// </summary>
        /// <param name="resultCode">The result code describing the result of the validation.</param>
        /// <param name="errorMessage">The message describing the error of the validation in the case that it failed.</param>
        public HmacValidationResult(int resultCode, string errorMessage)
        {
            ResultCode = resultCode;
            ErrorMessage = errorMessage;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="HmacValidationResult"/> using the specified result code.
        /// </summary>
        /// <param name="resultCode">The result code describing the result of the validation.</param>
        public HmacValidationResult(int resultCode)
            : this(resultCode, null)
        {
        }

        private static class NestedOk
        {
            public static readonly HmacValidationResult Instance = new HmacValidationResult(HmacValidationResultCode.Ok);
        }
    }
}