# Email Templates

This file contains the content for transactional emails sent by the AfyaFlow auth service.

---

## 1. Email Verification (`email_verification`)

**Subject:** Verify Your Email Address for AfyaFlow

**Body:**

Hi {{first_name}},

Welcome to AfyaFlow! To complete your registration and secure your account, please use the following One-Time Password (OTP):

# **{{otp_code}}**

This code will expire in 10 minutes. If you did not request this, please ignore this email.

Thanks,
The AfyaFlow Team

---

## 2. Password Reset (`password_reset`)

**Subject:** Your AfyaFlow Password Reset Request

**Body:**

Hi {{first_name}},

We received a request to reset the password for your AfyaFlow account. Please use the following token to complete the process.

**Reset Token:**
`{{reset_token}}`

This token is valid for 10 minutes. If you did not request a password reset, please disregard this email and contact our support team if you have concerns.

Thanks,
The AfyaFlow Team

---

## 3. MFA One-Time Password (`mfa_otp`)

**Subject:** Your AfyaFlow Login Verification Code

**Body:**

Hi {{first_name}},

Please use the following verification code to complete your login:

# **{{otp_code}}**

This code will expire shortly. If you did not attempt to log in, please secure your account immediately or contact support.

Thanks,
The AfyaFlow Team

---

## 4. MFA Setup OTP (`mfa_setup_otp`)

**Subject:** Your AfyaFlow MFA Setup Code

**Body:**

Hi {{first_name}},

To complete the setup of your new MFA method, please use the following verification code:

# **{{otp_code}}**

This code will expire in 10 minutes. If you did not request this, please ignore this email.

Thanks,
The AfyaFlow Team

---

## 5. Password Reset OTP (`password_reset_otp`)

**Subject:** Your AfyaFlow Password Reset Code

**Body:**

Hi {{first_name}},

We received a request to reset the password for your AfyaFlow account. Please use the following One-Time Password (OTP) to complete the process:

# **{{otp_code}}**

This code is valid for 10 minutes. If you did not request a password reset, please disregard this email.

Thanks,
The AfyaFlow Team

---

## 6. Password Changed Notification (`password_changed_notification`)

**Subject:** Your AfyaFlow Password Has Been Changed

**Body:**

Hi {{first_name}},

This is a confirmation that the password for your AfyaFlow account has been successfully changed.

If you did not make this change, please reset your password immediately using the "Forgot Password" link on the login page and contact our support team.

Thanks,
The AfyaFlow Team 