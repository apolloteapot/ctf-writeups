import binascii
import os
import re

import aiofiles
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from quart import current_app, Quart, request, redirect, url_for, render_template, flash, make_response
from quart_auth import AuthUser, AuthManager, current_user, login_required, login_user, logout_user, Unauthorized
import synapse.cortex as s_cortex
import synapse.telepath as s_telepath
import synapse.lib.time as s_time

def get_secret_key() -> str:
    k = os.getenv("CHAL_SECRET_KEY")
    if k is None:
        k = binascii.hexlify(get_random_bytes(32))

    return k

def get_cortex_url() -> str:
    u = os.getenv("CHAL_CORTEX_URL")
    if u is None:
        raise ValueError("couldn't get cortex URL from $CHAL_CORTEX_URL")

    return u

async def get_base_view() -> str:
    v = os.getenv("CHAL_CORTEX_VIEW")
    if v is None:
        v = await current_app.cortex.callStorm(r"return($lib.view.get().iden)")

    return v

BASE_VIEW_GUID = None

async def cortex_nodes(query, opts = {}) -> list:
    return [n[1] async for n in current_app.cortex.storm(query, opts=opts) if n[0] == "node"]

class User(AuthUser):
    def __init__(self, auth_id):
        super().__init__(auth_id)

        self._resolved = False
        self._is_admin = False
        self._view = None
    
    async def _resolve(self):
        if not self._resolved:
            self._view = (await current_app.cortex.callStorm(r"auth:creds=(thunderstruck,$u) -(hasview)> hash:md5 return($node.value())", opts={"vars": {"u": self.auth_id}, "view": BASE_VIEW_GUID}))
            self._is_admin = (await current_app.cortex.count(r"auth:creds=(thunderstruck,$u) +#role.admin", opts={"vars": {"u": self.auth_id}, "view": self._view})) == 1

            self._resolved = True
    
    @property
    async def is_admin(self):
        await self._resolve()
        return self._is_admin
    
    @property
    async def view(self):
        await self._resolve()
        return self._view

    @classmethod
    def get_salt(cls) -> bytes:
        return get_random_bytes(16)
    
    @classmethod
    def get_pw_hash(cls, password: str | bytes, salt: bytes) -> str:
    
        if isinstance(password, str):
            password = password.encode()
        
        return SHA256.new(password + salt).hexdigest()

    @classmethod
    async def login_user(cls, username: str, password: str) -> bool:
        try:
            passwdhash_node = (await cortex_nodes(r"auth:creds=(thunderstruck,$u) :passwdhash -> *", opts={"vars": {"u": username}, "view": BASE_VIEW_GUID}))[0]
            sha256 = passwdhash_node[1]["props"]["hash:sha256"]
            salt = binascii.unhexlify(passwdhash_node[1]["props"]["salt"])

            return cls.get_pw_hash(password, salt) == sha256
        except IndexError:
            return False

    @classmethod
    async def register_user(cls, username: str, password: str) -> bool:
        salt = cls.get_salt()
        pwhash = cls.get_pw_hash(password, salt)

        if (await current_app.cortex.count(r"auth:creds=(thunderstruck,$u)", opts={"vars": {"u": username}, "view": BASE_VIEW_GUID})) == 1:
            return False

        if not (await current_app.cortex.count(r"[ auth:creds=(thunderstruck,$u) :user=$u :passwdhash={[it:auth:passwdhash=(thunderstruck,$h) :hash:sha256=$h :salt=$s]} ]", opts={"vars": {"u": username, "h": pwhash, "s": salt}, "view": BASE_VIEW_GUID})) == 1:
            return False

        await current_app.cortex.callStorm(r"$newview = $lib.view.get($v).fork(name=`thunderstruck_{$u}`) $newview.set(nomerge, $lib.true) auth:creds=(thunderstruck,$u) [+(hasview)> {[hash:md5=$newview.iden]}]", opts={"vars": {"v": BASE_VIEW_GUID, "u": username}, "view": BASE_VIEW_GUID})
        if not (await current_app.cortex.count(r"auth:creds=(thunderstruck,$u) -(hasview)> hash:md5", opts={"vars": {"u": username}, "view": BASE_VIEW_GUID})) == 1:
            return False

        return True

async def _lookup_ip(ip) -> bool:
    return await current_app.cortex.count(f"inet:ipv4={ip}", opts={"vars": {"ip": ip}, "view": await current_user.view}) > 0

async def _lookup_md5(h) -> bool:
    return await current_app.cortex.count(f"hash:md5={h}", opts={"vars": {"h": h}, "view": await current_user.view}) > 0

async def _lookup_sha1(h) -> bool:
    return await current_app.cortex.count(f"hash:sha1={h}", opts={"vars": {"h": h}, "view": await current_user.view}) > 0

async def _lookup_sha256(h) -> bool:
    return await current_app.cortex.count(f"hash:sha256={h}", opts={"vars": {"h": h}, "view": await current_user.view}) > 0

async def _lookup_sha512(h) -> bool:
    return await current_app.cortex.count(f"hash:sha512={h}", opts={"vars": {"h": h}, "view": await current_user.view}) > 0

app = Quart("thunderstruck")
app.config["QUART_AUTH_COOKIE_SECURE"] = False
app.secret_key = get_secret_key()

auth_manager = AuthManager()
auth_manager.user_class = User

@app.before_serving
async def init_telepath():
    async with s_telepath.withTeleEnv():
        app.cortex = await s_telepath.openurl(get_cortex_url())

        global BASE_VIEW_GUID
        BASE_VIEW_GUID = await get_base_view()

@app.after_serving
async def close_telepath():
    await app.cortex.fini()

@app.get("/")
async def index():
    return await render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
async def register():
    if request.method == "POST":
        form = await request.form
        if not ("username" in form and "password" in form):
            await flash("Invalid form!")
            return redirect(url_for("login"))

        if not await User.register_user(form["username"], form["password"]):
            await flash("Failed to register, try a new username")
            return redirect(url_for("register"))

        await flash("Successfully registered, please login")
        return redirect(url_for("index"))
    else:
        return await render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
async def login():
    if request.method == "POST":
        form = await request.form
        if not ("username" in form and "password" in form):
            await flash("Invalid form!")
            return redirect(url_for("login"))

        if not await User.login_user(form["username"], form["password"]):
            await flash("Invalid credentials!")
            return redirect(url_for("login"))

        login_user(User(form["username"]))
        return redirect(url_for("index"))
    else:
        return await render_template("login.html")

@app.get("/logout")
async def logout():
    logout_user()
    return redirect(url_for("index"))

IPV4_PAT = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
HASH_PAT = re.compile(r"[0-9a-f]+")
@app.route("/lookup", methods=["GET", "POST"])
@login_required
async def lookup():
    if request.method == "POST":
        form = await request.form

        found = False
        good_lookup = True
        if IPV4_PAT.findall(form["query"]):
            found = await _lookup_ip(form["query"])
        elif HASH_PAT.findall(form["query"]):
            if len(form["query"]) == 32:
                found = await _lookup_md5(form["query"])
            elif len(form["query"]) == 40:
                found = await _lookup_sha1(form["query"])
            elif len(form["query"]) == 64:
                found = await _lookup_sha256(form["query"])
            elif len(form["query"]) == 128:
                found = await _lookup_sha512(form["query"])
            else:
                good_lookup = False
        else:
            good_lookup = False
        
        return await render_template("lookup.html", indicator=form["query"], good_lookup=good_lookup, found=found)
    else:
        return await render_template("lookup.html")

@app.route("/admin", methods=["GET", "POST"])
@login_required
async def admin():
    if not await current_user.is_admin:
        await flash("You must be an admin to do that!")
        return redirect(url_for("index"))
    else:
        if request.method == "GET":
            num_nodes = await current_app.cortex.count(r".created", opts={"view": await current_user.view})
            last_created = s_time.repr(await current_app.cortex.callStorm(r".created | max .created | return(.created)", opts={"view": await current_user.view}))
            ingest_ts, ingest_code = await current_app.cortex.callStorm(r"meta:event#ingest | max .created | return((.created, :summary))", opts={"view": await current_user.view})
            counts = await current_app.cortex.callStorm(r"return($lib.view.get().getFormCounts())")

            return await render_template("admin.html", num_nodes=num_nodes, last_created=last_created, ingest_ts=s_time.repr(ingest_ts), ingest_code=ingest_code, counts=counts)
        else:
            # TODO: fix ingest job running!
            flash("Broken :(")
            return redirect(url_for("admin"))

@app.errorhandler(Unauthorized)
async def redirect_to_login(*_):
    await flash("You must be logged in to do that!")
    return redirect(url_for("login"))

auth_manager.init_app(app)

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.run(debug=True)