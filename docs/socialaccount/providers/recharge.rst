Recharge
--------

You will need to register a Recharge partner app to obtain a client ID.

App registration
****************

With a Recharge partner account, you can create a new app at::

    https://partners.getrecharge.com

Note that, unlike most OAuth providers, the callback (redirect) URL and the
scopes are fixed at app registration time -- they are not passed along in the
authorization request. Register a callback URL such as::

    https://{{yourdomain}}.com/accounts/recharge/login/callback/

Setting up provider
*******************

* ``name``, up to you to choose (optional)
* ``client_id``, is called "Client ID"
* ``secret``, leave this blank -- Recharge's token exchange authenticates
  using only the client ID, no client secret is involved.

Usage
*****

The authorization URL is a per-store install URL, so the login endpoint must
be passed the store's domain via the query parameter matching the store's
ecommerce platform (``myshopify_domain``, ``mybigcommerce_domain`` or
``shop_domain``), e.g.::

    /accounts/recharge/login/?myshopify_domain=yourstore.myshopify.com

Since Recharge does not round-trip a ``state`` parameter to the callback, the
login state is matched based on the most recently issued state. As a
substitute one-time binding, the store domain the login was initiated for is
stashed in the state, and the callback is rejected unless Recharge echoes the
same store domain back.

After the token exchange, the store is identified via the ``/store`` API
resource (this requires the ``read_store`` scope on the app), whose stable
store ID is used as the account UID.
