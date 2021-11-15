vcl 4.0;

import std;
import directors;

backend server1 { # Define one backend
	.host = "127.0.0.1";    # IP or Hostname of backend
		.port = "8080";           # Port Apache or whatever is listening
		.max_connections = 300; # That's it

		.probe = {
#.url = "/"; # short easy way (GET /)
# We prefer to only do a HEAD /
			.request =
				"HEAD / HTTP/1.1"
				"Host: localhost"
				"Connection: close"
				"User-Agent: Varnish Health Probe";

			.interval  = 5s; # check the health of each backend every 5 seconds
				.timeout   = 1s; # timing out after 1 second.
				.window    = 5;  # If 3 out of the last 5 polls succeeded the backend is considered healthy, otherwise it will be marked as sick
				.threshold = 3;
		}

	.first_byte_timeout     = 300s;   # How long to wait before we receive a first byte from our backend?
		.connect_timeout        = 5s;     # How long to wait for a backend connection?
		.between_bytes_timeout  = 2s;     # How long to wait between bytes received from our backend?
}

acl purgers {
# ACL we'll use later to allow purges
	"localhost";
	"127.0.0.1";
	"::1";
}

sub vcl_init {
# Called when VCL is loaded, before any requests pass through it.
# Typically used to initialize VMODs.

	new vdir = directors.round_robin();
	vdir.add_backend(server1);
# vdir.add_backend(server...);
# vdir.add_backend(servern);
}


sub vcl_recv
{
# Set backend hint for non cachable objects.
#        set req.backend_hint = lb.backend();


# Routing logic. Pass a request to an appropriate Varnish node.
# See https://info.varnish-software.com/blog/creating-self-routing-varnish-cluster for more info.
	unset req.http.x-cache;
#        set req.backend_hint = cluster.backend(req.url);
#        set req.http.x-shard = req.backend_hint;
#        if (req.http.x-shard != server.identity) {
#            return(pass);
#        }
#        set req.backend_hint = lb.backend();

#  if (req.http.Host) {
#   set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
#  }

	unset req.http.X-Forwarded-For;
	set    req.http.X-Forwarded-For = client.ip;

	unset req.http.proxy;
	set req.url = std.querysort(req.url);

# Allow purging
	if (req.method == "PURGE") {
		if (client.ip !~ purgers) { # purge is the ACL defined at the begining
# Not from an allowed IP? Then die with an error.
			return (synth(405, "This IP is not allowed to send PURGE requests."));
		}
		if (req.http.X-Host) {
			set req.http.host = req.http.X-Host;
		}
# If you got this stage (and didn't error out above), purge the cached result
		return (purge);
	}

	if (req.method == "BAN") {
		if (client.ip !~ purgers) {
			return(synth(405, "This IP is not allowed to send PURGE requests."));
		}

		if (req.http.Cache-Tags) {
			ban("obj.http.Cache-Tags ~ " + req.http.Cache-Tags);
		} else {
			return (synth(403, "Cache-Tags header missing."));
		}

		if (req.http.X-Url) {
			ban("obj.http.X-Url == " + req.http.X-Url);
		} else {
			return (synth(403, "X-Url header missing."));
		}

		if (req.http.Purge-Cache-Tags) {
			ban(  "obj.http.X-Host == " + req.http.host + " && obj.http.Purge-Cache-Tags ~ " + req.http.Purge-Cache-Tags);
		} else {
			return (synth(403, "Purge-Cache-Tags header missing."));
		}

		if (req.http.X-Drupal-Cache-Tags) {
			ban("obj.http.X-Drupal-Cache-Tags ~ " + req.http.X-Drupal-Cache-Tags);
		} else {
			return (synth(403, "X-Drupal-Cache-Tags header missing."));
		}

#    else {
#      ban("obj.http.X-Host == " + req.http.host + " && obj.http.X-Url ~ " + req.url);
#      #ban("req.http.host == " + req.http.host + "&& req.url == " + req.url);
#     }
		return(synth(200, "Ban added" + req.http.host));

	}

# Only deal with "normal" types
	if (req.method != "GET" &&
			req.method != "HEAD" &&
			req.method != "PUT" &&
			req.method != "POST" &&
			req.method != "TRACE" &&
			req.method != "OPTIONS" &&
			req.method != "PATCH" &&
			req.method != "DELETE") {
		/* Non-RFC2616 or CONNECT which is weird. */
		return (pipe);
	}

	if (req.http.Upgrade ~ "(?i)websocket") {
		return (pipe);
	}

	if (req.method != "GET" && req.method != "HEAD") {
		return (pass);
	}

	if (req.url ~ "^/(cron|install|update)\.php$" && client.ip !~ purgers) {

		return (synth(404, "Not Found."));
	}

	if (req.url ~ "^/admin/content/backup_migrate/export") {
		return (pipe);
	}

# Some generic URL manipulation, useful for all templates that follow
# First remove the Google Analytics added parameters, useless for our backend
	if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
		set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
		set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
		set req.url = regsub(req.url, "\?&", "?");
		set req.url = regsub(req.url, "\?$", "");
	}

# Strip hash, server doesn't need it.
	if (req.url ~ "\#") {
		set req.url = regsub(req.url, "\#.*$", "");
	}

# Strip a trailing ? if it exists
	if (req.url ~ "\?$") {
		set req.url = regsub(req.url, "\?$", "");
	}

# Some generic cookie manipulation, useful for all templates that follow
# Remove the "has_js" cookie
	set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

# Remove any Google Analytics based cookies
	set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "_gat=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "__atuv.=[^;]+(; )?", "");
	set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

	if (req.http.cookie ~ "^\s*$") {
		unset req.http.cookie;
	}

#if (req.http.Cache-Control ~ "(?i)no-cache") {
#if (client.ip ~ purge) {
# Ignore requests via proxy caches and badly behaved crawlers
# like msnbot that send no-cache with every request.
#if (! (req.http.Via || req.http.User-Agent ~ "(?i)bot" || req.http.X-Purge)) {
#set req.hash_always_miss = true; # Doesn't seems to refresh the object in the cache
#return(purge); # Couple this with restart in vcl_purge and X-Purge header to avoid loops
#}
#}
#}

	if(req.http.Accept-Encoding ~ "br" && req.url !~
			"\.(jpg|png|gif|gz|mp3|mov|avi|mpg|mp4|swf|wmf)$") {
		set req.http.X-brotli = "true";
	}


	if (req.http.Accept-Encoding) {
		if (req.url ~ "\.(jpeg|jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf|flv)$") {
			unset req.http.Accept-Encoding;
		} elsif (req.http.Accept-Encoding ~ "gzip") {
			set req.http.Accept-Encoding = "gzip";
		} elsif (req.http.Accept-Encoding ~ "deflate" &&
				req.http.user-agent !~ "MSIE") {
			set req.http.Accept-Encoding = "deflate";
		} else {
			unset req.http.Accept-Encoding;
		}
	}

# Varnish 4 fully supports Streaming, so set do_stream in vcl_backend_response()
	if (req.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
		unset req.http.Cookie;
		return (hash);
	}

# Remove all cookies for static files
	if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
		unset req.http.Cookie;
		return (hash);
	}

# Send Surrogate-Capability headers to announce ESI support to backend
	set req.http.Surrogate-Capability = "key=ESI/1.0";

	if (req.http.Authorization) {
		return (pass);
	}

	if (req.url ~ "^/status\.php$" ||
			req.url ~ "^/update\.php" ||
			req.url ~ "^/install\.php" ||
			req.url ~ "^/admin" ||
			req.url ~ "^/admin/.*$" ||
			req.url ~ "^/user" ||
			req.url ~ "^/user/.*$" ||
			req.url ~ "^/users/.*$" ||
			req.url ~ "^/info/.*$" ||
			req.url ~ "^/flag/.*$" ||
			req.url ~ "^.*/ajax/.*$" ||
			req.url ~ "^.*/ahah/.*$") {
		return (pass);
	}

	return (hash);
}



sub vcl_pipe {

# Note that only the first request to the backend will have
# X-Forwarded-For set.  If you use X-Forwarded-For and want to
# have it set for all requests, make sure to have:
# set bereq.http.connection = "close";
# here.  It is not set by default as it might break some broken web
# applications, like IIS with NTLM authentication.

set bereq.http.Connection = "Close";

# Implementing websocket support (https://www.varnish-cache.org/docs/4.0/users-guide/vcl-example-websockets.html)
	if (req.http.upgrade) {
		set bereq.http.upgrade = req.http.upgrade;
	}

	return (pipe);
}

sub vcl_pass {
# Called upon entering pass mode. In this mode, the request is passed on to the backend, and the
# backend's response is passed on to the client, but is not entered into the cache. Subsequent
# requests submitted over the same client connection are handled normally.

 return (pass);
}

# The data on which the hashing will take place
sub vcl_hash {

	hash_data(req.url);

	if (req.http.host) {
		hash_data(req.http.host);
	} else {
		hash_data(server.ip);
	}

	if(req.http.X-brotli == "true" && req.http.X-brotli-unhash != "true") {
		hash_data("brotli");
	}

# hash cookies for requests that have them
	if (req.http.Cookie) {
		hash_data(req.http.Cookie);
	}

# Cache the HTTP vs HTTPs separately
	if (req.http.X-Forwarded-Proto) {
		hash_data(req.http.X-Forwarded-Proto);
	}
}

sub vcl_hit {

	if (obj.ttl >= 0s) {
# A pure unadultered hit, deliver it
		return (deliver);
	}

# if (!std.healthy(req.backend_hint) && (obj.ttl + obj.grace > 0s)) {
#   return (deliver);
# } else {
#   return (miss);
# }

# We have no fresh fish. Lets look at the stale ones.
	if (std.healthy(req.backend_hint)) {
# Backend is healthy. Limit age to 10s.
		if (obj.ttl + 10s > 0s) {
#set req.http.grace = "normal(limited)";
			return (deliver);
		}
	} else {
# backend is sick - use full grace
		if (obj.ttl + obj.grace > 0s) {
#set req.http.grace = "full";
			return (deliver);
		}
	}
}

sub vcl_miss {
# Called after a cache lookup if the requested document was not found in the cache. Its purpose
# is to decide whether or not to attempt to retrieve the document from the backend, and which
# backend to use.

	return (fetch);
}

sub vcl_backend_fetch
{
	if(bereq.http.X-brotli == "true") {
		set bereq.http.Accept-Encoding = "br";
		unset bereq.http.X-brotli;
	}
}


# Handle the HTTP request coming from our backend
sub vcl_backend_response {
# Called after the response headers has been successfully retrieved from the backend.

	set beresp.http.X-Url = bereq.url;
	set beresp.http.X-Host = bereq.http.host;

# Pause ESI request and remove Surrogate-Control header
	if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
		unset beresp.http.Surrogate-Control;
		set beresp.do_esi = true;
	}

# Enable cache for all static files
	if (bereq.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
		unset beresp.http.set-cookie;
	}

# Varnish 4 fully supports Streaming, so use streaming here to avoid locking.
	if (bereq.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
		unset beresp.http.set-cookie;
		set beresp.do_stream = true;
	}

	if (beresp.http.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|mp4|ogg|swf)$") {
		set beresp.do_gzip = false;
	}
	else {
		set beresp.do_gzip = true;
		set beresp.http.X-Cache = "ZIP";
	}
	if (beresp.http.content-type ~ "text") {
		set beresp.do_gzip = true;
	}

# To prevent accidental replace, we only filter the 301/302 redirects for now.
	if (beresp.status == 301 || beresp.status == 302) {
		set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
	}

# Set 2min cache if unset for static files
	if (beresp.ttl <= 0s || beresp.http.Set-Cookie || beresp.http.Vary == "*") {
		set beresp.ttl = 120s;
		set beresp.uncacheable = true;
		return (deliver);
	}

# Don't cache 50x responses
	if (beresp.status == 500 || beresp.status == 502 || beresp.status == 503 || beresp.status == 504) {
		return (abandon);
	}

# Don't cache ajax requests
	if(beresp.http.X-Requested-With == "XMLHttpRequest" || bereq.url ~ "nocache") {
		set beresp.http.X-Cacheable = "NO:Ajax";
		set beresp.uncacheable = true;
		return (deliver);
	}

	if (beresp.http.Cache-Control !~ "max-age" || beresp.http.Cache-Control ~ "max-age=0") {
		set beresp.http.Cache-Control = "public, max-age=3600, stale-while-revalidate=360, stale-if-error=43200";
	}

# Optionally set a larger TTL for pages with less than the timeout of cache TTL
	if (beresp.ttl < 3600s) {
		set beresp.http.Cache-Control = "public, max-age=3600, stale-while-revalidate=360, stale-if-error=43200";
	}


# Allow stale content, in case the backend goes down.
# make Varnish keep all objects for 6 hours beyond their TTL
    set beresp.ttl = 60m;
	set beresp.grace = 6h;

	return (deliver);
}

# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
# Called before a cached object is delivered to the client.

	if (obj.hits > 0) { # Add debug header to see if it's a HIT/MISS and the number of hits, disable when not needed
		set resp.http.X-Cache = "HIT";
	} else {
		set resp.http.X-Cache = "MISS";
	}

	set resp.http.X-Cache-Hits = obj.hits;

# Remove some headers: Cache tags, PHP version, Apache version & OS

	unset resp.http.Link;
	unset resp.http.Purge-Cache-Tags;
	unset resp.http.Server;
	unset resp.http.Via;
	unset resp.http.X-Host;
	unset resp.http.X-Cache-Contexts;
	unset resp.http.X-Cache-Tags;
	unset resp.http.X-Drupal-Cache;
	unset resp.http.X-Drupal-Cache-Tags;
	unset resp.http.X-Generator;
	unset resp.http.X-Powered-By;
	unset resp.http.X-Url;
	unset resp.http.X-Varnish;

	return (deliver);
}

sub vcl_purge {
# Only handle actual PURGE HTTP methods, everything else is discarded
	if (req.method == "PURGE") {
# restart request
		set req.http.X-Purge = "Yes";
		return(restart);
	}

	if (req.url !~ "\.(jpg|png|gif|gz|mp3|mov|avi|mpg|mp4|swf|wmf)$" &&
			!req.http.X-brotli-unhash) {
		if (req.http.X-brotli == "true") {
			set req.http.X-brotli-unhash = "true";
			set req.http.Accept-Encoding = "gzip";
		} else {
			set req.http.X-brotli-unhash = "false";
			set req.http.Accept-Encoding = "br";
		}
		return (restart);
	}
}

sub vcl_synth {
	if (resp.status == 720) {
# We use this special error status 720 to force redirects with 301 (permanent) redirects
# To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
		set resp.http.Location = resp.reason;
		set resp.status = 301;
		return (deliver);
	} elseif (resp.status == 721) {
# And we use error status 721 to force redirects with a 302 (temporary) redirect
# To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
		set resp.http.Location = resp.reason;
		set resp.status = 302;
		return (deliver);
	}
	if (resp.status == 503) {
#synthetic(std.fileread("/etc/varnish/error503.html"));
		set resp.http.Content-Type = "text/html; charset=utf-8";
		set resp.http.Retry-After = "5";
		synthetic( {"
				<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
				<html>
				<head>
				<title>"} + resp.status + " " + resp.reason + {"</title>
				<link href='http://fonts.googleapis.com/css?family=Oswald:400,700' rel='stylesheet' type='text/css'>

				</head>
				<body style="background-color:#444; font-family: 'Oswald', sans-serif;">
				<h1 style="color:#DD8363;">Error "} + resp.status + " " + {"</h1>
				<p style="color:#5F88C4; ">"} + resp.reason + {"</p>
				<h3 style="color:white;">CEPI Says</h3>
				<p style="color:#bdb76b;">XID: "} + req.xid + {"</p>
				<p style="color:#bdb76b;">Edge-Server: "} + server.hostname + {"</p>
				<hr>
				<p style="color:#65b042;">2.0</p>
				</body>
				</html>
				"} );
	}
	return (deliver);
}


sub vcl_fini {
#  # Called when VCL is discarded only after all requests have exited the VCL.
#  # Typically used to clean up VMODs.
	return (ok);
}

#vim: syntax=vcl ts=2 sw=2 sts=4 sr noet
