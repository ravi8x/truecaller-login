package info.androidhive.truecaller_login

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.truecaller.android.sdk.oAuth.CodeVerifierUtil
import com.truecaller.android.sdk.oAuth.TcOAuthCallback
import com.truecaller.android.sdk.oAuth.TcOAuthData
import com.truecaller.android.sdk.oAuth.TcOAuthError
import com.truecaller.android.sdk.oAuth.TcSdk
import com.truecaller.android.sdk.oAuth.TcSdkOptions
import info.androidhive.truecaller_login.databinding.ActivityLoginBinding
import java.math.BigInteger
import java.security.SecureRandom

class LoginActivity : AppCompatActivity(), TcOAuthCallback {
    private val TAG = "LoginActivity"

    private val binding by lazy(LazyThreadSafetyMode.NONE) {
        ActivityLoginBinding.inflate(layoutInflater)
    }
    private var stateRequested: String? = null
    private var codeVerifier: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(binding.root)

        binding.btnLogin.setOnClickListener {
            loginWithTruecaller()
        }
    }

    /**
     * Method to trigger truecaller login
     * */
    private fun loginWithTruecaller() {
        // Keeping it in try / catch as it's crashing on few devices
        try {
            // init true caller sdk
            initTruecaller()

            val canUseTruecaller = canUseTrueCaller()

            if (canUseTruecaller) {
                // this will show true caller bottom sheet
                stateRequested = BigInteger(130, SecureRandom()).toString(32)
                stateRequested?.let { TcSdk.getInstance().setOAuthState(it) }

                // requesting profile, phone scopes
                TcSdk.getInstance().setOAuthScopes(arrayOf("profile", "phone"))

                codeVerifier = CodeVerifierUtil.generateRandomCodeVerifier()

                codeVerifier?.let { verifier ->
                    val codeChallenge = CodeVerifierUtil.getCodeChallenge(verifier)
                    codeChallenge?.let {
                        TcSdk.getInstance().setCodeChallenge(it)
                    } ?: Toast.makeText(
                        this, R.string.truecaller_code_challange_error, Toast.LENGTH_LONG
                    ).show()
                }

                TcSdk.getInstance().getAuthorizationCode(this)
            } else {
                // Can't use truecaller on this device
                Toast.makeText(this, R.string.truecaller_cant_use_error, Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(
                this, "Unknown error occurred while login - ${e.message}", Toast.LENGTH_LONG
            ).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == TcSdk.SHARE_PROFILE_REQUEST_CODE) {
            TcSdk.getInstance().onActivityResultObtained(this, requestCode, resultCode, data)
        }
    }

    // returns true if true caller app present in the mobile
    private fun canUseTrueCaller() = TcSdk.getInstance().isOAuthFlowUsable

    /**
     * Initialising truecaller SDK by configuring the custom variables
     * More info on customisation is here
     * https://docs.truecaller.com/truecaller-sdk/android/oauth-sdk-3.1.0/integration-steps/customisation
     * */
    private fun initTruecaller() {
        val tcSdkOptions = TcSdkOptions.Builder(this, this)
            .buttonColor(ContextCompat.getColor(this, R.color.color_primary))
            .buttonTextColor(ContextCompat.getColor(this, R.color.white))
            .loginTextPrefix(TcSdkOptions.LOGIN_TEXT_PREFIX_TO_GET_STARTED)
            .ctaText(TcSdkOptions.CTA_TEXT_CONTINUE)
            .buttonShapeOptions(TcSdkOptions.BUTTON_SHAPE_ROUNDED)
            .footerType(TcSdkOptions.FOOTER_TYPE_SKIP)
            .consentTitleOption(TcSdkOptions.SDK_CONSENT_HEADING_LOG_IN_TO).build()

        TcSdk.init(tcSdkOptions)
    }

    /**
     * On successful login, send token, state and scopes to your backend and validate the data
     * More info is here
     * https://docs.truecaller.com/truecaller-sdk/android/oauth-sdk-3.1.0/integration-steps/integrating-with-your-backend/fetching-user-token
     * */
    override fun onSuccess(tcOAuthData: TcOAuthData) {
        val state = tcOAuthData.state
        val token = tcOAuthData.authorizationCode
        val scopes = tcOAuthData.scopesGranted

        Toast.makeText(
            this,
            "Truecaller login is successful! Token:${token}, State:${state})",
            Toast.LENGTH_LONG
        ).show()
    }

    override fun onFailure(tcOAuthError: TcOAuthError) {
        Log.e(
            TAG,
            "Truecaller login error. Code:${tcOAuthError.errorCode}, Message:${tcOAuthError.errorMessage}"
        )

        Toast.makeText(
            this,
            "Truecaller login error. Code:${tcOAuthError.errorCode}, Message:${tcOAuthError.errorMessage}",
            Toast.LENGTH_LONG
        ).show()
    }

    override fun onVerificationRequired(tcOAuthError: TcOAuthError?) {
        Log.e(
            TAG,
            "Truecaller onVerificationRequired:${tcOAuthError?.errorCode}, Message:${tcOAuthError?.errorMessage}"
        )
        Toast.makeText(
            this,
            "Error! Truecaller verification is required. Error Code:${tcOAuthError?.errorCode}, Message:${tcOAuthError?.errorMessage})",
            Toast.LENGTH_LONG
        ).show()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Release the resources taken by the SDK
        TcSdk.clear()
    }
}