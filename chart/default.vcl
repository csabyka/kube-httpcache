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
	"192.168.1.0"/24;
}

sub vcl_init {
	new vdir = directors.round_robin();
	vdir.add_backend(server1);
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

    if (req.restarts == 0) {
        if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        }
        else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }

    # Only allow PURGE requests from IP addresses in the 'purge' ACL.
    if (req.method == "PURGE") {
        if (!client.ip ~ purgers) {
            return (synth(405, "Not allowed."));
        }
        return (hash);
    }

    # Only allow BAN requests from IP addresses in the 'purge' ACL.
    if (req.method == "BAN") {
        # Same ACL check as above:
        if (!client.ip ~ purgers) {
            return (synth(403, "Not allowed."));
        }

        # Logic for the ban, using the Cache-Tags header. For more info
        # see https://github.com/geerlingguy/drupal-vm/issues/397.
        if (req.http.Cache-Tags) {
            ban("obj.http.Cache-Tags ~ " + req.http.Cache-Tags);
        }
        else {
            return (synth(403, "Cache-Tags header missing."));
        }

        # Throw a synthetic page so the request won't go to the backend.
        return (synth(200, "Ban added."));
    }

	if (req.method == "URIBAN") {
		ban("req.http.host == " + req.http.host + " && req.url == " + req.url);
		# Throw a synthetic page so the request won't go to the backend.
		return (synth(200, "Ban added."));
	}


unset req.http.cookie;
#	unset req.http.X-Forwarded-For;
        unset req.http.proxy;
	set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
	set req.http.X-Forwarded-For = client.ip;
	set req.url = std.querysort(req.url);


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

	# never cache ajax requests
	if (req.http.X-Requested-With == "XMLHttpRequest") {
		return(pass);
	}

	if (req.url ~ "^/(cron|install|update)\.php$" && client.ip !~ purgers) {
		return (synth(404, "Not Found."));
	}

	if (req.url ~ "^/admin/content/backup_migrate/export") {
		return (pipe);
	}

	if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
		set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
		set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
		set req.url = regsub(req.url, "\?&", "?");
		set req.url = regsub(req.url, "\?$", "");
	}

	if (req.url ~ "\#") {
		set req.url = regsub(req.url, "\#.*$", "");
	}

	if (req.url ~ "\?$") {
		set req.url = regsub(req.url, "\?$", "");
	}

	set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");
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
#	if (req.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
#		unset req.http.Cookie;
#		return (hash);
#	}

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

	set bereq.http.Connection = "Close";

	if (req.http.upgrade) {
		set bereq.http.upgrade = req.http.upgrade;
	}

	return (pipe);
}

sub vcl_pass {

#return (pass);
}

sub vcl_hash {

	hash_data(req.url);

	if (req.http.host) {
		hash_data(req.http.host);
	} else {
		hash_data(server.ip);
	}

	if (req.http.Cookie) {
		hash_data(req.http.Cookie);
	}

}

sub vcl_hit {

	if (obj.ttl >= 0s) {
		return (deliver);
	}

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

	return (fetch);
}

sub vcl_backend_fetch
{

}


sub vcl_backend_response {

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
		set beresp.http.Cache-Control = "public, max-age=604800";
		set beresp.http.Expires = "" + (now + 604800s);

	}

# Varnish 4 fully supports Streaming, so use streaming here to avoid locking.
	if (bereq.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
		unset beresp.http.set-cookie;
		set beresp.do_stream = true;
		set beresp.http.Expires = "" + (now + 604800s);
	}

# To prevent accidental replace, we only filter the 301/302 redirects for now.
	if (beresp.status == 301 || beresp.status == 302) {
		set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
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
#	if (beresp.ttl < 3600s) {
#		set beresp.http.Cache-Control = "public, max-age=3600, stale-while-revalidate=360, stale-if-error=43200";
#	}

    if (beresp.status == 404) {
        set beresp.ttl = 10m;
    }


	set beresp.ttl = 60m;
	set beresp.grace =24h;

	return (deliver);
}

sub vcl_deliver {

	if (obj.hits > 0) {
		set resp.http.X-Cache = "HIT";
	} else {
		set resp.http.X-Cache = "MISS";
	}

	set resp.http.X-Cache-Hits = obj.hits;

# Remove some headers: Cache tags, PHP version, Apache version & OS
#	unset resp.http.Link;
	unset resp.http.X-Cache-Hits;
#	unset resp.http.Purge-Cache-Tags;
	unset resp.http.Server;
	unset resp.http.Via;
	unset resp.http.X-Host;
#	unset resp.http.X-Cache-Contexts;
#	unset resp.http.X-Cache-Tags;
#	unset resp.http.X-Drupal-Cache;
#	unset resp.http.X-Drupal-Cache-Tags;
#	unset resp.http.X-Drupal-Cache-Contexts;
	unset resp.http.X-Generator;
	unset resp.http.X-Powered-By;
	unset resp.http.X-Url;
	unset resp.http.X-Varnish;

	return (deliver);
}

sub vcl_purge {
# Only handle actual PURGE HTTP methods, everything else is discarded
	if (req.method == "PURGE") {
		set req.method = "GET";
		set req.http.X-Purge = "Yes";
		set req.http.X-Purger = "Purged";
		return(restart);
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
		set resp.status = 503;
		set resp.http.Content-Type = "text/html; charset=utf-8";
		set resp.http.Retry-After = "5";
		synthetic( {"<!DOCTYPE html>
		<html>
			<head>
				<title>Error "} + resp.status + " " + resp.reason + {"</title>
			</head>
			<body>
				<h1>Error "} + resp.status + " " + resp.reason + {"</h1>
				<p>"} + resp.reason + " from IP " + std.ip(req.http.X-Real-IP, "0.0.0.0") + {"</p>
				<h3>Guru Meditation:</h3>
				<p>XID: "} + req.xid + {"</p>
				<hr>
				<p>Varnish cache server</p>
			</body>
		</html>
				"} );
	}
	unset req.http.connection;
	return (deliver);
}


sub vcl_fini {
	return (ok);
}

#vim: syntax=vcl ts=2 sw=2 sts=4 sr noet
