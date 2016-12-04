namespace Donker.Hmac.Validation
{
    /// <summary>
    /// Describes the result of a request validation.
    /// </summary>
    public class HmacValidationResultCode
    {
        /// <summary>
        /// No error occured.
        /// </summary>
        public const int Ok = 0;
        /// <summary>
        /// The date header could not be found.
        /// </summary>
        public const int DateMissing = 1;
        /// <summary>
        /// The date expired or is set in the future.
        /// </summary>
        public const int DateInvalid = 2;
        /// <summary>
        /// The username is required but not found.
        /// </summary>
        public const int UsernameMissing = 3;
        /// <summary>
        /// No key was found.
        /// </summary>
        public const int KeyMissing = 4;
        /// <summary>
        /// The Content-MD5 body hash does not match the one in the header.
        /// </summary>
        public const int BodyHashMismatch = 5;
        /// <summary>
        /// The authorization header could not be found or was empty.
        /// </summary>
        public const int AuthorizationMissing = 6;
        /// <summary>
        /// The authorization header was in an incorrect format.
        /// </summary>
        public const int AuthorizationInvalid = 7;
        /// <summary>
        /// The signatures do not match.
        /// </summary>
        public const int SignatureMismatch = 8;
    }
}