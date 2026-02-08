# 🎪 Mikhael's Custom Secure Auth - The Login Plugin That Doesn't Cost You a Kidney!

![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)
![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-brightgreen.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-orange.svg)

## 🚗 HOLD UP! Before You Drive Off...

**ARE YOU TIRED** of those rickety-dickity login plugins that charge you an arm, a leg, AND your grandma's secret cookie recipe just to let users log into your dang website?

**WELL FOLKS**, do I have a deal for you!

Step right up and feast your eyes on **Mikhael's Custom Secure Auth** - the login plugin that's slicker than a greased otter, more secure than Fort Knox, and **COMPLETELY FREE**! That's right, I said **FREE**! No monthly subscriptions, no "pro" versions locked behind a paywall, no nickel-and-diming for basic features!

### 🎉 What's the Catch?

**THERE IS NO CATCH!** I'm basically giving this baby away! Why? Because I built it for my own NSFW site and figured, "Hey, why not share the love?" Consider it community service!

---

## 🎯 Why This Plugin Will Change Your Life (Probably)

Listen, I'm not gonna beat around the bush here. Other plugins? They're like buying a "luxury" car that breaks down every 50 miles and the dealer charges you $500 just to look at the engine.

**This plugin?** It's like getting a fully-loaded sports car with:
- ✨ **Zero enumeration** - Stalkers can't figure out if your users exist (privacy first, baby!)
- 🔒 **Fort Knox security** - HMAC tokens, rate limiting, honeypots, reCAPTCHA... we've got more security than a paranoid squirrel
- 🎨 **Grid-based form builder** - Build registration forms like you're playing with LEGO blocks
- 🎭 **Fun username generator** - Because "user12345" is boring as heck
- 🚫 **Username policy enforcement** - Keep the trolls and their offensive usernames OUT
- 📧 **Custom email templates** - Make your emails look professional, not like they came from 1997
- 🎪 **Hybrid registration flows** - With password, without password, we don't judge!

---

## 🏁 Features That'll Knock Your Socks Off

### 🔐 Security Features (The Good Stuff)

**"But wait, there's more!"** - Yeah, I'm saying it. Because there IS more!

#### Anti-Stalker Technology™
- **Zero-enumeration authentication** - Can't figure out if an email or username exists. Stalkers hate this one weird trick!
- **Generic error messages** - "Unable to complete registration" instead of "Username exists" - vague is beautiful
- **Password recovery that doesn't snitch** - Always says "email sent if account exists" even when it doesn't

#### The 403 Gauntlet (Security Theater That Actually Works)
- **HMAC token-based CSRF protection** - Not your grandma's nonces
- **IP-based rate limiting** - Try too many times? BANNED! (Temporarily, we're not monsters)
- **Configurable lockout duration** - 1 hour? 24 hours? You're the boss!
- **Honeypot spam protection** - Bots fall for it every time, it's adorable
- **Google reCAPTCHA v3** - The invisible kind, so it doesn't annoy your users
- **Referer validation** - No funny business from other domains
- **REST API lockdown** - Require authentication or whitelist namespaces
- **Security event logging** - Know when the bad guys try to knock on your door

#### Username Policy Management (The Bouncer)
- **Reserved words** - "admin", "root", "moderator" - nope, nope, nope
- **Strict content blocking** - Substring match for the REALLY bad words
- **Isolated content blocking** - Word boundary match for the kinda-bad words
- **Generic violations** - "Content against our guidelines" - classy AND secure

### 🎨 Customization (Make It Yours)

#### Grid-Based Form Builder
Drag, drop, done! Build registration forms with:
- Username fields
- Email fields
- Password fields
- First name, last name
- Custom fields galore!
- Password confirmation
- **And it's all visual!** No PhD in Computer Science required!

#### Email Templates
- **Activation emails** - "Click here to activate your account" (but prettier)
- **Recovery emails** - "Forgot your password? No judgment here"
- **Template variables** - `{user_name}`, `{site_name}`, `{set_password_url}` - it's like Mad Libs for grown-ups

#### Page Mapping
Point the plugin to YOUR pages:
- Custom login page
- Custom registration page
- Custom password recovery page
- Custom password reset page
- **Dropdown selectors** - No more copy-pasting URLs like a caveman

### 🚀 User Experience (The Cherry on Top)

- **Password strength indicator** - "Weak", "Medium", "Strong" - it's like a video game health bar
- **Password visibility toggle** - Show/hide passwords because we've all typed the wrong thing
- **Auto-login after registration** - Configurable! (Flow A1 vs Flow A2)
- **Auto-login after password reset** - Optional! (Some people like to live dangerously)
- **Fun username generator** - "SneakyPanda47" - generated in milliseconds
- **Custom redirect after login** - Send 'em wherever you want
- **Privacy warnings** - "Hey, maybe don't use your real name?" - good advice

### 🎪 Shortcodes (Easy as Pie)

Plop these bad boys anywhere:

```
[auth_login]              - Login form
[auth_register]           - Registration form
[auth_lost_password]      - Password recovery form
[auth_set_password]       - Password reset/activation form
[auth_button]             - Auth button (login/logout/register links)
```

**That's it!** No rocket science degree needed!

---

## 📦 Installation (So Easy, Your Grandma Could Do It)

### Method 1: The WordPress Way

1. **Download** the plugin (you're probably already here, so good job!)
2. **Upload** to `/wp-content/plugins/mikhael-custom-login/`
3. **Activate** through the 'Plugins' menu in WordPress
4. **Configure** by going to **Settings > Secure Auth**
5. **Create pages** for login, registration, password recovery, and password reset
6. **Add shortcodes** to those pages
7. **Test** it out!
8. **Profit!** (Not literally, this is free)

### Method 2: The Git Clone Way (For the Cool Kids)

```bash
cd wp-content/plugins/
git clone https://github.com/yourusername/mikhael-custom-login.git
```

Then activate in WordPress. Boom. Done.

---

## ⚙️ Configuration (The Fun Part)

### Step 1: Page Mapping

Go to **Settings > Secure Auth > Page Mapping & Logic**

1. **Create 4 pages** in WordPress:
   - "Login"
   - "Register"
   - "Forgot Password"
   - "Reset Password"

2. **Add shortcodes** to each page:
   - Login page: `[auth_login]`
   - Register page: `[auth_register]`
   - Forgot Password page: `[auth_lost_password]`
   - Reset Password page: `[auth_set_password]`

3. **Map the pages** in the settings using the dropdown selectors

4. **Configure redirect** - Where should users go after login? Home? Profile? The moon?

5. **Set token expiry** - Default is 30 minutes (like a pizza delivery guarantee)

### Step 2: Security Settings (The 403 Vault)

Go to **Settings > Secure Auth > Security**

- **Honeypot** - Enable it (it's free real estate against bots)
- **Max failed attempts** - Default is 5 (adjust if your users have fat fingers)
- **Lockout duration** - Default is 1 hour (time for them to think about what they've done)
- **reCAPTCHA** - Add your site key and secret key (get 'em from Google)
- **REST API Security** - Disable user enumeration endpoint (yes, do it)
- **REST API Authentication** - Require auth for all REST requests (optional, but recommended)
- **Whitelisted Namespaces** - Add `custom-secure-auth` (already there, you're welcome)

### Step 3: Grid Builder (Registration Form Designer)

Go to **Settings > Secure Auth > Registration Grid Builder**

**Drag and drop fields like you're playing Tetris:**
- Add fields
- Rearrange them
- Set which ones are required
- Choose field widths (50%, 100%, etc.)
- Add placeholders
- **Fun Username Generator** - Toggle on/off
- **Privacy Warning** - Customize the message

**Pro Tip:** Test the form after you build it. Seriously. Do it.

### Step 4: Username Policy (The Bouncer Settings)

Go to **Settings > Secure Auth > Username Policy**

**Reserved Words** - Comma-separated list:
```
admin, administrator, root, system, moderator, staff, owner
```

**Restricted Words (Strict Block)** - Substring match for offensive content:
```
fuck, shit, nazi, etc. (you get the idea)
```

**Restricted Words (Isolated Block)** - Word boundary match:
```
ass, dick, sex, etc. (the "eh, depends on context" words)
```

**Boundary Match Toggle** - Apply word boundaries to reserved words too

### Step 5: Email Templates

Go to **Settings > Secure Auth > Email Templates**

**Activation Email:**
- Subject: `Activate Your Account - {site_name}`
- Body: Use HTML! Use variables! Go wild!

**Recovery Email:**
- Subject: `Reset Your Password - {site_name}`
- Body: Same deal!

**Available Variables:**
- `{user_name}` - Obvious
- `{site_name}` - Also obvious
- `{set_password_url}` - The magic link
- `{user_email}` - In case they forgot

---

## 🎓 Usage Examples (Real World Scenarios)

### Scenario 1: Basic Login/Registration Site

**Pages to create:**
1. `/login` - Add `[auth_login]`
2. `/register` - Add `[auth_register]`
3. `/forgot-password` - Add `[auth_lost_password]`
4. `/reset-password` - Add `[auth_set_password]`

**Settings:**
- Map all 4 pages
- Enable reCAPTCHA
- Set redirect to `/dashboard` or `/profile`
- Enable auto-login after registration

**Result:** Users can register, login, and reset passwords. Chef's kiss. 👌

### Scenario 2: NSFW Content Site (My Use Case)

**Extra considerations:**
- Enable **username policy** with strict content filtering
- Add **privacy warning** about using anonymous usernames
- Enable **fun username generator** for anonymity
- Disable **auto-login after registration** (force email activation)
- Enable **REST API authentication** to lock down content
- Disable **user enumeration** (super important for privacy)

**Result:** Privacy-first authentication that protects your users from stalkers and weirdos.

### Scenario 3: Membership Site

**Extra features:**
- Use **hybrid registration** (email-only, set password later)
- Custom **email templates** with your branding
- **Reserved words** for premium usernames
- Redirect after login to **welcome page** or **onboarding**

**Result:** Professional registration flow with email verification.

---

## 🔧 Troubleshooting (When Things Go Sideways)

### "I'm getting a blank screen!"

**Solution:** Check your PHP error logs. Probably a plugin conflict. Disable other plugins one by one until you find the culprit.

### "The token isn't working!"

**Solution:**
1. Check if REST API is accessible: `yoursite.com/wp-json/custom-secure-auth/get-token`
2. Check if JavaScript is loading (open browser console)
3. Check if `AUTH_KEY` is defined in `wp-config.php` (it should be by default)

### "Users aren't receiving emails!"

**Solution:**
1. Check your WordPress email settings
2. Test with an SMTP plugin like WP Mail SMTP
3. Check spam folders
4. Verify the email templates aren't broken (missing variables, invalid HTML)

### "Rate limiting is locking out legitimate users!"

**Solution:**
- Increase **Max Failed Attempts** (5 is default, try 10)
- Decrease **Lockout Duration** (1 hour is default, try 15 minutes)
- Check if Cloudflare or another proxy is causing issues

### "The form looks ugly!"

**Solution:**
- Add custom CSS to your theme
- Use the **Button CSS Classes** field to match your theme's buttons
- The plugin uses minimal styling on purpose (it's not opinionated)

### "I need help!"

**Solution:**
- Check the **FEATURE_ROADMAP.md** for planned features
- Open an issue on GitHub (if this is open-source by the time you're reading this)
- Read the inline code comments (they're extensive)
- Ask me nicely (I'm friendly!)

---

## 🤝 Compatibility

**WordPress Version:** 5.0 or higher (probably works on 4.9 too, but no promises)

**PHP Version:** 7.4 or higher (8.0+ recommended)

**Tested With:**
- WordPress 6.4+
- PHP 8.1, 8.2
- Cloudflare proxy (we detect `HTTP_CF_CONNECTING_IP`)
- Common themes (Divi, Elementor, Astra, etc.)

**Known Conflicts:**
- None! (Yet. Let me know if you find any)

**Integrations:**
- Works with **mikhael-nsfw-restrictions** plugin (governance logging)
- Works with **[nsfw_tos_interceptor]** shortcode

---

## 🛡️ Security Best Practices

Listen, I've built this thing to be secure out of the box, but you gotta do your part too:

### 1. Use HTTPS
Seriously. It's 2026. Get a free Let's Encrypt certificate and enable SSL. Passwords over HTTP is like shouting your credit card number in a crowded mall.

### 2. Enable reCAPTCHA
Google's giving it away for free. Use it. Bots are relentless.

### 3. Set Reasonable Rate Limits
- 5 failed attempts is good for most sites
- 10 if your users have butterfingers
- 3 if you're paranoid (or running a high-security site)

### 4. Monitor Security Logs
Check **Settings > Secure Auth > Security** for the blocked namespaces log. If you see a lot of failed attempts from one IP, that's a red flag.

### 5. Keep WordPress Updated
Old WordPress = security holes. Update it. Update your themes. Update your plugins. Be responsible.

### 6. Use Strong Passwords
The plugin enforces 8 characters minimum, but encourage your users to go longer. "password123" is not a strong password. "MyC@tIsN@med!Whiskers1983" is better.

### 7. Regular Backups
Not directly related to this plugin, but seriously, back up your database. When (not if) something goes wrong, you'll thank me.

---

## 🎁 What You're Getting (Recap)

Let's be real here. You're getting:

✅ **43+ features** that would cost you $200+/year with other plugins
✅ **Zero-enumeration security** that protects your users' privacy
✅ **Custom form builder** without needing to code
✅ **HMAC-based CSRF protection** (fancy!)
✅ **Rate limiting and lockouts** to stop brute force attacks
✅ **reCAPTCHA integration** to stop bots
✅ **Username policy enforcement** to keep the riffraff out
✅ **Custom email templates** to look professional
✅ **Security event logging** to know what's happening
✅ **REST API security** to lock down your endpoints
✅ **Shortcodes galore** to make your life easy

**And you're paying:** $0.00

**That's right, ZERO DOLLARS!**

---

## 🚀 Roadmap (What's Coming Next)

Check out **FEATURE_ROADMAP.md** for the full scoop, but here's the highlight reel:

### v2.1.0 - Security Hardening (Coming Soon™)
- Two-Factor Authentication (email-based OTP)
- Session Management (force logout, concurrent session limits)
- Login notification emails
- Admin bar login link redirection

### v2.2.0 - Modern Authentication
- Social login (Google, Discord, Facebook)
- Magic link passwordless authentication
- Profile management shortcodes

### v2.3.0 - User Experience
- Remember Me functionality
- Role-based redirects
- Login history viewer

### v3.0.0 - Premium Features (But Still Free!)
- WebAuthn/Passkeys
- Registration moderation
- Geolocation blocking
- Visual login page customizer

---

## 📜 License

**GPL-2.0+** - That's the "do whatever you want, just don't sue me" license.

You can:
- ✅ Use it commercially
- ✅ Modify it
- ✅ Distribute it
- ✅ Sublicense it
- ✅ Use it for client projects

You cannot:
- ❌ Hold me liable if something breaks
- ❌ Remove the license header (that's just rude)

---

## 🙏 Credits

**Author:** Mikhael Love
**Contributors:** Claude (AI Assistant) - The hardest working AI in the business
**Inspiration:** Too many overpriced login plugins and not enough privacy
**Coffee Consumed:** Too much
**Bugs Squashed:** Many

---

## 💖 Support This Project

This plugin is **completely free**, but if you want to say thanks:

- ⭐ **Star it on GitHub** (when it's open-source)
- 🐛 **Report bugs** (nicely, please)
- 💡 **Suggest features** (check FEATURE_ROADMAP.md first)
- 📢 **Tell your friends** (spread the love)
- ☕ **Buy me a coffee** (kidding... unless?)

---

## 📞 Contact

**Issues?** Open a GitHub issue
**Questions?** Read this README again (seriously, it's all here)
**Feature Requests?** Check FEATURE_ROADMAP.md first
**Compliments?** I'll take 'em!

---

## 🎬 Final Words

Look, I could've charged $99/year for this plugin. Other developers do it all the time. But I'm not about that life.

I built this for **my own site**, battle-tested it with **real users**, fixed all the bugs (okay, most of the bugs), and now I'm giving it to **YOU** for **FREE**.

Why? Because the WordPress community has given me so much over the years, and this is my way of giving back.

So go ahead, download it. Use it. Break it. Fix it. Make it better. Share it with your friends.

And if you ever see me at a WordCamp, the beer's on you. Deal? Deal.

**Now get out there and build something awesome!** 🚀

---

**P.S.** - If you read this whole README, you're a trooper. Here's a cookie 🍪 (not the tracking kind, the delicious kind).

**P.P.S.** - Seriously though, enable reCAPTCHA. The bots are coming.

**P.P.P.S.** - Check the **FEATURE_ROADMAP.md** if you want to see what's coming next. Spoiler: It's cool stuff.

---

Made with ❤️, ☕, and a healthy dose of sarcasm by Mikhael Love
